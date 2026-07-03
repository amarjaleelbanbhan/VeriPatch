import type { ScannedVuln, ScanOutput, StepResult } from '../../core/models/index.js';
import { escapeMarkdown } from '../../shared/sanitize.js';

/**
 * Human/audit-grade evidence report in Markdown (blueprint §5.2/§13). Every
 * externally sourced string (advisory id/summary, package name, log tails)
 * is escaped before it enters the document — a hostile package name or
 * advisory summary must render as inert text, never break the layout or
 * inject formatting.
 */
export function renderScanReportMarkdown(scan: ScanOutput): string {
  const lines: string[] = [];
  lines.push(`# VeriPatch report`, '');
  lines.push(
    `Generated ${escapeMarkdown(scan.generatedAt)} by VeriPatch ${escapeMarkdown(scan.tool.version)}.`,
    '',
  );
  lines.push(
    `**Summary:** ${String(scan.summary.critical)} critical, ${String(scan.summary.high)} high, ` +
      `${String(scan.summary.medium)} medium, ${String(scan.summary.low)} low — ` +
      `${String(scan.summary.verified)} verified.`,
    '',
  );

  if (scan.scan.degraded) lines.push('> ⚠️ Degraded scan: no lockfile was present.', '');
  if (scan.scan.stale)
    lines.push('> ⚠️ Advisory data may be stale (served offline from cache).', '');

  if (scan.vulns.length === 0) {
    lines.push('No vulnerabilities found.');
    return lines.join('\n');
  }

  lines.push('| ID | Severity | Package | Fix | Verdict |', '|---|---|---|---|---|');
  for (const vuln of scan.vulns) {
    lines.push(`| ${tableRow(vuln)} |`);
  }
  lines.push('');

  for (const vuln of scan.vulns.filter((v) => v.verification !== null)) {
    lines.push(renderVerificationSection(vuln), '');
  }

  return lines.join('\n');
}

function tableRow(vuln: ScannedVuln): string {
  const id = escapeMarkdown(vuln.id);
  const severity = vuln.severity.label;
  const pkg = escapeMarkdown(`${vuln.pkg} ${vuln.installed}`);
  const fix = vuln.fix.feasible
    ? escapeMarkdown(`→ ${vuln.fix.to} (${vuln.fix.bumpType})`)
    : '_no fix_';
  const verdict = vuln.verification?.confidence ?? '_not verified_';
  return [id, severity, pkg, fix, verdict].join(' | ');
}

function renderVerificationSection(vuln: ScannedVuln): string {
  const verification = vuln.verification;
  if (verification === null) return '';
  const lines = [
    `## ${escapeMarkdown(vuln.id)} — ${verification.confidence}`,
    '',
    `Run \`${escapeMarkdown(verification.runId)}\`, started ${escapeMarkdown(verification.startedAt)}.`,
    '',
  ];
  for (const step of verification.steps) {
    lines.push(renderStepDetails(step));
  }
  if (verification.residualRisks.length > 0) {
    lines.push('**Residual risks:**');
    for (const risk of verification.residualRisks) lines.push(`- ${escapeMarkdown(risk)}`);
  }
  return lines.join('\n');
}

function renderStepDetails(step: StepResult): string {
  const icon = step.status === 'pass' ? '✅' : step.status === 'skipped' ? '⏭️' : '❌';
  const testInfo =
    step.testCounts !== undefined
      ? ` (${String(step.testCounts.passed)}/${String(step.testCounts.total)} passed)`
      : '';
  return [
    `<details><summary>${icon} ${step.step} — ${step.status}${testInfo}</summary>`,
    '',
    '```',
    escapeMarkdown(step.logTail),
    '```',
    '',
    '</details>',
    '',
  ].join('\n');
}

/** GitHub-flavored variant for a sticky PR comment (blueprint §6 report --format pr-comment). */
export function renderPrComment(scan: ScanOutput): string {
  const body = renderScanReportMarkdown(scan);
  return [`<!-- veripatch-report -->`, body].join('\n');
}
