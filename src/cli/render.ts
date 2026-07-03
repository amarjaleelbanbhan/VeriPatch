import type { ScanOutput, ScannedVuln, SeverityLabel } from '../core/models/index.js';

/**
 * Human-readable scan output (blueprint §6): ranked table, degraded/stale
 * banners, summary footer, verify hint. --no-color strips every ANSI code.
 */
const ANSI = {
  reset: '\u001B[0m',
  bold: '\u001B[1m',
  gray: '\u001B[90m',
  red: '\u001B[31m',
  yellow: '\u001B[33m',
  cyan: '\u001B[36m',
} as const;

const SEVERITY_COLOR: Record<SeverityLabel, keyof typeof ANSI> = {
  CRITICAL: 'red',
  HIGH: 'red',
  MEDIUM: 'yellow',
  LOW: 'gray',
};

export interface RenderOptions {
  color: boolean;
}

function paint(text: string, color: keyof typeof ANSI, options: RenderOptions): string {
  return options.color ? `${ANSI[color]}${text}${ANSI.reset}` : text;
}

function bold(text: string, options: RenderOptions): string {
  return options.color ? `${ANSI.bold}${text}${ANSI.reset}` : text;
}

export function renderScan(output: ScanOutput, options: RenderOptions): string {
  const lines: string[] = [];

  if (output.scan.degraded) {
    lines.push(
      paint('⚠ degraded: no lockfile — results incomplete, verify disabled', 'yellow', options),
    );
  }
  if (output.scan.stale) {
    lines.push(
      paint('⚠ offline: serving cached advisory data that may be stale', 'yellow', options),
    );
  }
  if (output.scan.dataErrors > 0) {
    lines.push(
      paint(
        `⚠ ${String(output.scan.dataErrors)} advisor${output.scan.dataErrors === 1 ? 'y' : 'ies'} dropped due to invalid data`,
        'yellow',
        options,
      ),
    );
  }
  if (lines.length > 0) lines.push('');

  if (output.vulns.length === 0) {
    lines.push(paint('✅ No vulnerabilities found.', 'cyan', options));
    return lines.join('\n');
  }

  lines.push(renderTable(output.vulns, options));
  lines.push('');
  lines.push(renderSummaryLine(output, options));
  lines.push('');
  lines.push(
    `Run ${bold('veripatch verify <id>', options)} to prove a fix is safe before applying it.`,
  );

  return lines.join('\n');
}

function renderTable(vulns: ScannedVuln[], options: RenderOptions): string {
  const headers = ['ID', 'SEV', 'PKG', 'BUMP', 'STRATEGY', 'NOTE'];
  const rows = vulns.map((v) => [
    v.id,
    v.severity.label,
    v.fix.feasible ? `${v.pkg} ${v.fix.from}→${v.fix.to}` : `${v.pkg} ${v.installed}`,
    v.fix.feasible ? v.fix.bumpType : '-',
    v.fix.feasible ? v.fix.strategy : '-',
    v.fix.feasible ? '' : (v.fix.reason ?? 'no fix available'),
  ]);

  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]?.length ?? 0)));

  const renderRow = (cells: string[], colorRow?: (cell: string, i: number) => string): string =>
    cells.map((c, i) => (colorRow ? colorRow(c, i) : c).padEnd(widths[i] ?? 0)).join('  ');

  const lines = [bold(renderRow(headers), options), renderRow(widths.map((w) => '-'.repeat(w)))];
  rows.forEach((row, i) => {
    const vuln = vulns[i];
    const severityColor = vuln !== undefined ? SEVERITY_COLOR[vuln.severity.label] : 'gray';
    lines.push(
      renderRow(row, (cell, colIdx) => (colIdx === 1 ? paint(cell, severityColor, options) : cell)),
    );
  });
  return lines.join('\n');
}

function renderSummaryLine(output: ScanOutput, options: RenderOptions): string {
  const { critical, high, medium, low } = output.summary;
  const total = critical + high + medium + low;
  return bold(
    `${String(total)} vulnerabilit${total === 1 ? 'y' : 'ies'} found — ` +
      `${String(critical)} critical, ${String(high)} high, ${String(medium)} medium, ${String(low)} low`,
    options,
  );
}
