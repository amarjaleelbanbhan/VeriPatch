import { describe, expect, it } from 'vitest';
import {
  isGating,
  skippedStep,
  stepFromExec,
  tailLog,
} from '../../../../../src/adapters/sandbox/steps/shared.js';
import type { ExecOutcome } from '../../../../../src/adapters/sandbox/docker.js';

const ESC = '';

function outcome(overrides: Partial<ExecOutcome> = {}): ExecOutcome {
  return { exitCode: 0, output: '', timedOut: false, durationMs: 42, ...overrides };
}

describe('tailLog', () => {
  it('keeps only the last 40 lines', () => {
    const lines = Array.from({ length: 100 }, (_, i) => `line ${String(i)}`);
    const tail = tailLog(lines.join('\n'));
    expect(tail.split('\n')).toHaveLength(40);
    expect(tail.split('\n')[0]).toBe('line 60');
  });

  it('strips ANSI and sanitizes control characters', () => {
    expect(tailLog(`${ESC}[31mred${ESC}[0m`)).toBe('red');
  });
});

describe('stepFromExec', () => {
  it('maps exit 0 to pass with the exit code recorded', () => {
    const step = stepFromExec('install', outcome({ exitCode: 0 }));
    expect(step).toMatchObject({ step: 'install', status: 'pass', exitCode: 0 });
  });

  it('maps a non-zero exit to fail', () => {
    const step = stepFromExec('build', outcome({ exitCode: 1 }));
    expect(step).toMatchObject({ step: 'build', status: 'fail', exitCode: 1 });
  });

  it('maps a timeout without a meaningless exit code', () => {
    const step = stepFromExec('test', outcome({ timedOut: true, exitCode: -1 }));
    expect(step.status).toBe('timeout');
    expect(step.exitCode).toBeUndefined();
  });

  it('rounds duration and truncates the log tail', () => {
    const step = stepFromExec('install', outcome({ durationMs: 12.7, output: 'a\nb\nc' }));
    expect(step.durationMs).toBe(13);
    expect(step.logTail).toBe('a\nb\nc');
  });

  it('attaches testCounts only when provided', () => {
    const withCounts = stepFromExec('test', outcome(), {
      testCounts: { passed: 1, failed: 0, total: 1 },
    });
    expect(withCounts.testCounts).toEqual({ passed: 1, failed: 0, total: 1 });
    const without = stepFromExec('test', outcome());
    expect(without.testCounts).toBeUndefined();
  });
});

describe('skippedStep / isGating', () => {
  it('produces a zero-cost skipped marker', () => {
    expect(skippedStep('build')).toEqual({
      step: 'build',
      status: 'skipped',
      durationMs: 0,
      logTail: '',
    });
  });

  it('only fail and timeout gate the pipeline', () => {
    expect(isGating(stepFromExec('install', outcome({ exitCode: 1 })))).toBe(true);
    expect(isGating(stepFromExec('install', outcome({ timedOut: true })))).toBe(true);
    expect(isGating(stepFromExec('install', outcome({ exitCode: 0 })))).toBe(false);
    expect(isGating(skippedStep('build'))).toBe(false);
  });
});
