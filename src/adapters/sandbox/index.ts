import { randomUUID } from 'node:crypto';
import type { StepResult } from '../../core/models/index.js';
import type {
  AdvisorySource,
  LockfileParser,
  Sandbox,
  SandboxPlan,
  StepListener,
} from '../../core/ports.js';
import { ok, type Result } from '../../shared/result.js';
import { cleanupStagedProject, stageProjectCopy } from './copy.js';
import type { ContainerHandle, SandboxRuntime } from './docker.js';
import { NetworkPhaseManager } from './network.js';
import { runApplyStep } from './steps/apply.js';
import { runBuildStep } from './steps/build.js';
import { runInstallStep } from './steps/install.js';
import { runRescanStep } from './steps/rescan.js';
import { skippedStep, isGating } from './steps/shared.js';
import { runTestStep } from './steps/test.js';

/**
 * Dockerized verification pipeline (blueprint §2 data flow, §9 hardening):
 * copy -> apply -> install (registry-only) -> rescan (host-side rule engine)
 * -> isolate network -> build -> test (network none) -> teardown.
 *
 * Stops early once a step gates the run (fail/timeout) — remaining steps are
 * recorded 'skipped' rather than wasting the verify-timeout budget, since
 * computeConfidence's priority rules already determine the verdict.
 */
export class DockerSandbox implements Sandbox {
  constructor(
    private readonly runtime: SandboxRuntime,
    private readonly parser: LockfileParser,
    private readonly advisorySource: AdvisorySource,
  ) {}

  async run(plan: SandboxPlan, onStep?: StepListener): Promise<Result<StepResult[]>> {
    const runId = randomUUID();
    const timeoutMs = plan.config.verifyTimeoutMin * 60_000;
    const steps: StepResult[] = [];
    const emit = (step: StepResult): void => {
      steps.push(step);
      onStep?.(step);
    };

    const staged = stageProjectCopy(plan.projectDir);
    if (!staged.ok) return staged;
    emit({ step: 'copy', status: 'pass', durationMs: 0, logTail: '' });

    const network = new NetworkPhaseManager(this.runtime);
    const pull = await this.runtime.pullImageIfMissing(plan.config.sandboxImage);
    if (!pull.ok) {
      cleanupStagedProject(staged.value);
      return pull;
    }

    const networkMode = await network.createInstallNetwork(runId);
    if (!networkMode.ok) {
      cleanupStagedProject(staged.value);
      return networkMode;
    }

    const containerResult = await this.runtime.createHardenedContainer(
      plan.config.sandboxImage,
      staged.value.stagingDir,
      networkMode.value,
    );
    if (!containerResult.ok) {
      await network.teardown();
      cleanupStagedProject(staged.value);
      return containerResult;
    }
    const container = containerResult.value;

    try {
      await this.runSteps(container, network, staged.value.stagingDir, plan, timeoutMs, emit);
      return ok(steps);
    } finally {
      await container.teardown();
      await network.teardown();
      cleanupStagedProject(staged.value);
    }
  }

  private async runSteps(
    container: ContainerHandle,
    network: NetworkPhaseManager,
    stagingDir: string,
    plan: SandboxPlan,
    timeoutMs: number,
    emit: (step: StepResult) => void,
  ): Promise<void> {
    const apply = emitAndReturn(emit, await runApplyStep(container, plan.candidate, timeoutMs));
    if (isGating(apply)) {
      for (const name of ['install', 'rescan', 'build', 'test'] as const) emit(skippedStep(name));
      return;
    }

    const install = emitAndReturn(emit, await runInstallStep(container, timeoutMs));
    if (isGating(install)) {
      for (const name of ['rescan', 'build', 'test'] as const) emit(skippedStep(name));
      return;
    }

    const rescan = emitAndReturn(
      emit,
      await runRescanStep(this.parser, this.advisorySource, stagingDir, plan.candidate),
    );

    const isolated = await network.isolate(container.id);
    if (!isolated.ok) {
      emit(skippedStep('build'));
      emit(skippedStep('test'));
      return;
    }

    if (isGating(rescan)) {
      for (const name of ['build', 'test'] as const) emit(skippedStep(name));
      return;
    }

    const build = emitAndReturn(
      emit,
      await runBuildStep(container, plan.config.buildCommand, timeoutMs),
    );
    if (isGating(build)) {
      emit(skippedStep('test'));
      return;
    }

    emit(await runTestStep(container, plan.config.testCommand, timeoutMs));
  }
}

function emitAndReturn(emit: (step: StepResult) => void, step: StepResult): StepResult {
  emit(step);
  return step;
}

export { DockerRuntime } from './docker.js';
