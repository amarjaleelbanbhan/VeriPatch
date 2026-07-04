import type { ScanOutput, ScannedVuln, Vuln } from '../core/models/index.js';
import { matchVulnerabilities } from '../core/rules/match.js';
import { resolveFix } from '../core/rules/fix-resolver.js';
import { rankVulnerabilities, summarizeVulns } from '../core/rules/severity.js';
import type { AdvisorySource, LockfileParser } from '../core/ports.js';
import type { Result } from '../shared/result.js';
import { ok } from '../shared/result.js';
import type { Config } from '../shared/config.js';
import { VERIPATCH_VERSION } from '../shared/version.js';

/**
 * Orchestrates scan → advisories → match → rank → fix resolution (blueprint
 * §2 data flow, §6 `scan` command). Depends only on core-defined ports —
 * concrete adapters (lockfile parser, OSV client, cache) are constructed and
 * injected by the CLI composition root, never imported here directly.
 */
export interface ScanServiceDeps {
  parser: LockfileParser;
  advisorySource: AdvisorySource;
}

export interface ScanRequest {
  projectDir: string;
  severityThreshold: Config['severityThreshold'];
  ignore: string[];
  includeDevDeps: boolean;
}

/**
 * Real phase boundaries in the pipeline below — not a fabricated progress
 * bar. A caller (the CLI's spinner) gets to say "Parsing lockfile…" and
 * "Fetching advisories…" because those are genuinely the two slow steps,
 * not because the UI made up intermediate percentages.
 */
export type ScanPhase = 'lockfile' | 'advisories' | 'match';
export type ScanPhaseListener = (phase: ScanPhase) => void;

export async function runScan(
  deps: ScanServiceDeps,
  request: ScanRequest,
  onPhase?: ScanPhaseListener,
): Promise<Result<ScanOutput>> {
  onPhase?.('lockfile');
  const graphResult = deps.parser.parse(request.projectDir);
  if (!graphResult.ok) return graphResult;
  const graph = graphResult.value;

  onPhase?.('advisories');
  const advisoryResult = await deps.advisorySource.getAdvisories(graph.nodes);
  if (!advisoryResult.ok) return advisoryResult;
  const { advisories, stale, dataErrors } = advisoryResult.value;

  onPhase?.('match');
  const allVulns = matchVulnerabilities(graph.nodes, advisories);
  const ranked = rankVulnerabilities(allVulns, {
    severityThreshold: request.severityThreshold,
    ignore: request.ignore,
    includeDevDeps: request.includeDevDeps,
  });

  const vulns = ranked.map(toScannedVuln);

  return ok({
    schemaVersion: 1,
    tool: { name: 'VeriPatch', version: VERIPATCH_VERSION },
    generatedAt: new Date().toISOString(),
    scan: {
      lockfileVersion: graph.lockfileVersion,
      packageManager: graph.packageManager,
      degraded: graph.degraded,
      totalDeps: graph.nodes.length,
      dataErrors,
      stale,
    },
    vulns,
    summary: summarizeVulns(vulns),
  });
}

function toScannedVuln(vuln: Vuln): ScannedVuln {
  return {
    id: vuln.advisory.id,
    aliases: vuln.advisory.aliases,
    pkg: vuln.node.name,
    installed: vuln.node.version,
    severity: vuln.advisory.severity,
    dev: vuln.node.dev,
    paths: vuln.node.paths,
    fix: resolveFix(vuln),
    verification: null,
  };
}
