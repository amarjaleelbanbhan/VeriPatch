import type { ScanOutput, ScannedVuln, SeverityLabel } from '../core/models/index.js';
import {
  box,
  createPaint,
  explainStep,
  getSymbols,
  keyValueBlock,
  rule,
  table,
  type Tone,
  type UiOptions,
} from './ui/index.js';

/**
 * Human-readable `scan` output (blueprint §6): brand header, project summary
 * card, a ranked top-vulnerabilities table, a verification section that
 * explains — never just asserts — each real verdict, and a final
 * recommendation card. `--json` bypasses this file entirely; every string
 * printed here is derived from real `ScanOutput` fields, nothing invented.
 */
export type RenderOptions = UiOptions;

const SEVERITY_TONE: Record<SeverityLabel, Tone> = {
  CRITICAL: 'danger',
  HIGH: 'danger',
  MEDIUM: 'warning',
  LOW: 'muted',
};

const MAX_TABLE_ROWS = 8;

export function renderScan(output: ScanOutput, options: RenderOptions): string {
  const paint = createPaint(options.color);
  const sym = getSymbols(options.unicode);
  const lines: string[] = [];

  lines.push(...renderBrandHeader(options));
  lines.push('');

  const banners = renderBanners(output, options);
  if (banners.length > 0) {
    lines.push(...banners, '');
  }

  if (output.vulns.length === 0) {
    lines.push(
      ...box(
        [
          paint.boldTone(`${sym.pass} No known vulnerabilities found`, 'success'),
          paint.dim(
            `${String(output.scan.totalDeps)} package${output.scan.totalDeps === 1 ? '' : 's'} scanned` +
              (output.scan.packageManager !== null ? ` · ${output.scan.packageManager}` : ''),
          ),
        ],
        options,
      ),
    );
    return lines.join('\n');
  }

  lines.push(
    paint.bold(`${sym.bullet} Project Summary`),
    ...renderSummaryCard(output, options),
    '',
  );
  lines.push(
    paint.bold(`${sym.bullet} Top Vulnerabilities`),
    ...renderVulnTable(output.vulns, options),
    '',
  );

  const verificationSection = renderVerificationSection(output.vulns, options);
  if (verificationSection.length > 0) {
    lines.push(paint.bold(`${sym.bullet} Verification`), ...verificationSection, '');
  }

  lines.push(...renderFinalSummary(output, options));

  return lines.join('\n');
}

function renderBrandHeader(options: RenderOptions): string[] {
  const paint = createPaint(options.color);
  const sym = getSymbols(options.unicode);
  return [
    `${paint.boldTone(sym.brand, 'brand')} ${paint.bold('VeriPatch')}`,
    paint.dim("Don't just detect vulnerabilities — prove the fix is safe."),
  ];
}

function renderBanners(output: ScanOutput, options: RenderOptions): string[] {
  const paint = createPaint(options.color);
  const banners: string[] = [];

  if (output.scan.degraded) {
    banners.push(
      `${paint('⚠', 'warning')} degraded: no lockfile — results incomplete, ${paint.dim('verify disabled')}`,
    );
  }
  if (output.scan.stale) {
    banners.push(
      `${paint('⚠', 'warning')} offline: serving cached advisory data that may be stale`,
    );
  }
  if (output.scan.dataErrors > 0) {
    banners.push(
      `${paint('⚠', 'warning')} ${String(output.scan.dataErrors)} advisor${
        output.scan.dataErrors === 1 ? 'y' : 'ies'
      } dropped due to invalid data`,
    );
  }
  return banners;
}

function verificationStatusOf(vuln: ScannedVuln, options: RenderOptions): string {
  const paint = createPaint(options.color);
  const sym = getSymbols(options.unicode);
  if (vuln.verification === null) return paint.dim(`${sym.pending} not verified`);
  switch (vuln.verification.confidence) {
    case 'HIGH':
    case 'MEDIUM':
      return paint(`${sym.pass} verified`, 'success');
    case 'FAIL':
      return paint(`${sym.fail} failed`, 'danger');
    case 'INCONCLUSIVE':
      return paint(`${sym.warn} inconclusive`, 'warning');
  }
}

function renderVulnTable(vulns: ScannedVuln[], options: RenderOptions): string[] {
  const paint = createPaint(options.color);
  const shown = vulns.slice(0, MAX_TABLE_ROWS);

  const rows = table(
    shown,
    [
      { header: 'PACKAGE', cell: (v) => v.pkg },
      {
        header: 'SEVERITY',
        cell: (v) => paint.boldTone(v.severity.label, SEVERITY_TONE[v.severity.label]),
      },
      { header: 'CURRENT', cell: (v) => v.installed },
      {
        header: 'SAFE VERSION',
        cell: (v) => (v.fix.feasible ? v.fix.to : paint.dim('—')),
      },
      { header: 'VERIFICATION', cell: (v) => verificationStatusOf(v, options) },
    ],
    options,
  );

  const remaining = vulns.length - shown.length;
  if (remaining > 0) {
    rows.push(paint.dim(`… ${String(remaining)} more — run with --json for the full list`));
  }
  return rows;
}

function renderSummaryCard(output: ScanOutput, options: RenderOptions): string[] {
  const paint = createPaint(options.color);
  const { verifiedCount, reviewCount } = tallyVerification(output.vulns);

  const pairs: [string, string][] = [
    ['Package manager', output.scan.packageManager ?? paint.dim('unknown')],
    ['Packages scanned', String(output.scan.totalDeps)],
    [
      'Vulnerabilities',
      paint.boldTone(String(output.vulns.length), output.vulns.length > 0 ? 'danger' : 'success'),
    ],
    [
      'Verified fixes',
      verifiedCount > 0 ? paint.boldTone(String(verifiedCount), 'success') : String(verifiedCount),
    ],
    [
      'Manual review required',
      reviewCount > 0 ? paint.boldTone(String(reviewCount), 'warning') : String(reviewCount),
    ],
  ];
  return box(keyValueBlock(pairs), options);
}

function tallyVerification(vulns: ScannedVuln[]): { verifiedCount: number; reviewCount: number } {
  let verifiedCount = 0;
  let reviewCount = 0;
  for (const vuln of vulns) {
    if (vuln.verification === null) continue;
    if (vuln.verification.confidence === 'HIGH' || vuln.verification.confidence === 'MEDIUM') {
      verifiedCount++;
    } else {
      reviewCount++;
    }
  }
  return { verifiedCount, reviewCount };
}

/**
 * Explains a real verdict instead of just stamping it. Every line here comes
 * straight from that vuln's own `VerificationResult.steps` — a "Tests
 * passed" line only appears because the real `test` step's status was
 * literally 'pass'. Vulns never verified yet don't get an entry here at all;
 * inventing an explanation for a check that never ran would be exactly the
 * kind of fabricated verdict this tool exists to never produce.
 */
function renderVerificationSection(vulns: ScannedVuln[], options: RenderOptions): string[] {
  const paint = createPaint(options.color);
  const sym = getSymbols(options.unicode);
  const verified = vulns.filter((v) => v.verification !== null);
  if (verified.length === 0) return [];

  const lines: string[] = [];
  for (const vuln of verified.slice(0, 3)) {
    const result = vuln.verification;
    if (result === null) continue;
    const ok = result.confidence === 'HIGH' || result.confidence === 'MEDIUM';
    const header = `${ok ? paint(sym.pass, 'success') : paint(sym.warn, 'warning')} ${paint.bold(vuln.id)}  ${vuln.pkg} ${sym.arrow} ${vuln.fix.to}`;
    lines.push(header);

    if (ok) {
      const passedSteps = result.steps.filter((s) => s.status === 'pass');
      const explanation = passedSteps
        .filter((s) => ['rescan', 'build', 'test'].includes(s.step))
        .map((s) => explainStep(s.step));
      if (explanation.length > 0) {
        lines.push(`  ${explanation.map((e) => `${paint(sym.pass, 'success')} ${e}`).join('   ')}`);
      }
    } else {
      const failing = result.steps.find((s) => s.status === 'fail' || s.status === 'timeout');
      const reason =
        failing !== undefined
          ? `${failing.step} step ${failing.status === 'timeout' ? 'timed out' : 'failed'}`
          : (result.residualRisks[0] ?? 'verification did not confirm the fix');
      lines.push(`  ${paint('⚠', 'warning')} Requires manual review — ${reason}`);
    }
  }
  if (verified.length > 3) {
    lines.push(paint.dim(`… ${String(verified.length - 3)} more verified vulns — see report.md`));
  }
  return lines;
}

/**
 * The one section deliberately boxed for emphasis. "Risk reduction" here is
 * a real count of the severities eliminated by already-verified fixes — not
 * a fabricated score. There is no "time to apply" estimate: nothing in this
 * codebase measures that yet, and a made-up number would violate the same
 * verification-first principle the rest of the tool is built on.
 */
function renderFinalSummary(output: ScanOutput, options: RenderOptions): string[] {
  const paint = createPaint(options.color);
  const sym = getSymbols(options.unicode);
  const verifiedVulns = output.vulns.filter(
    (v) =>
      v.verification !== null &&
      (v.verification.confidence === 'HIGH' || v.verification.confidence === 'MEDIUM'),
  );

  if (verifiedVulns.length > 0) {
    const bySeverity = tallyBySeverity(verifiedVulns);
    const lines = [
      paint.boldTone(
        `${sym.pass} ${String(verifiedVulns.length)} verified fix${verifiedVulns.length === 1 ? '' : 'es'} ready to apply`,
        'success',
      ),
      '',
      `Removes ${describeSeverityTally(bySeverity)}`,
      '',
      `Run:  ${paint.bold(`veripatch update ${verifiedVulns[0]?.id ?? '<id>'}`)}`,
    ];
    return box(lines, options);
  }

  const feasible = output.vulns.filter((v) => v.fix.feasible);
  if (feasible.length > 0) {
    const top = feasible[0];
    const lines = [
      paint.boldTone(
        `${String(feasible.length)} fixable vulnerabilit${feasible.length === 1 ? 'y' : 'ies'} — none verified yet`,
        'warning',
      ),
      paint.dim('Prove a fix is safe in a sandbox before applying it:'),
      '',
      `Run:  ${paint.bold(`veripatch verify ${top?.id ?? '<id>'}`)}`,
    ];
    return box(lines, options);
  }

  return [
    paint.dim(rule(options)),
    paint.dim('No feasible fix is available for the vulnerabilities above.'),
  ];
}

function tallyBySeverity(vulns: ScannedVuln[]): Record<SeverityLabel, number> {
  const tally: Record<SeverityLabel, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const vuln of vulns) tally[vuln.severity.label]++;
  return tally;
}

function describeSeverityTally(tally: Record<SeverityLabel, number>): string {
  const labels = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).filter(
    (label) => tally[label] > 0,
  );
  const parts = labels.map((label) => `${String(tally[label])} ${label.toLowerCase()}`);
  const total = labels.reduce((sum, label) => sum + tally[label], 0);
  return `${parts.join(', ')} severity vulnerabilit${total === 1 ? 'y' : 'ies'}`;
}
