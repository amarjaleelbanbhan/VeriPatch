import type { Severity, SeverityLabel } from '../../core/models/index.js';

/**
 * CVSS v3.x base-score computation (first.org spec §7.1). OSV serves severity
 * as a vector string, not a number; we derive the score ourselves rather than
 * trust free-text severity fields.
 */

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC = { L: 0.77, H: 0.44 } as const;
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 } as const;
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 } as const;
const UI = { N: 0.85, R: 0.62 } as const;
const CIA = { H: 0.56, L: 0.22, N: 0 } as const;

export function scoreToLabel(score: number): SeverityLabel {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/** Look up a metric letter in its weight table without widening to "always defined". */
function lookup(table: Record<string, number>, key: string | undefined): number | undefined {
  return key === undefined ? undefined : table[key];
}

/** Parse a CVSS:3.0/3.1 vector into a base score, or undefined when unparsable. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!vector.startsWith('CVSS:3.0/') && !vector.startsWith('CVSS:3.1/')) return undefined;

  const metrics = new Map<string, string>();
  for (const part of vector.split('/').slice(1)) {
    const [key, value] = part.split(':');
    if (key !== undefined && value !== undefined) metrics.set(key, value);
  }

  const av = lookup(AV, metrics.get('AV'));
  const ac = lookup(AC, metrics.get('AC'));
  const ui = lookup(UI, metrics.get('UI'));
  const c = lookup(CIA, metrics.get('C'));
  const i = lookup(CIA, metrics.get('I'));
  const a = lookup(CIA, metrics.get('A'));
  const scope = metrics.get('S');
  const prTable = scope === 'C' ? PR_CHANGED : PR_UNCHANGED;
  const pr = lookup(prTable, metrics.get('PR'));

  if (
    av === undefined ||
    ac === undefined ||
    ui === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined ||
    pr === undefined ||
    (scope !== 'U' && scope !== 'C')
  ) {
    return undefined;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    scope === 'C' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return 0;
  const raw =
    scope === 'C'
      ? Math.min(1.08 * (impact + exploitability), 10)
      : Math.min(impact + exploitability, 10);
  return roundUp1(raw);
}

/** Spec-mandated "round up to 1 decimal" (not banker's rounding). */
function roundUp1(value: number): number {
  const intInput = Math.round(value * 100_000);
  if (intInput % 10_000 === 0) return intInput / 100_000;
  return (Math.floor(intInput / 10_000) + 1) / 10;
}

const TEXT_LABELS: Record<string, SeverityLabel> = {
  LOW: 'LOW',
  MODERATE: 'MEDIUM',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
};

/**
 * Best severity available: CVSS v3 vector when present, else the database's
 * text label with a representative mid-band score, else a conservative default
 * of MEDIUM (unknown risk is not "low" risk).
 */
export function deriveSeverity(cvssVectors: string[], databaseLabel: string | undefined): Severity {
  for (const vector of cvssVectors) {
    const score = cvss3BaseScore(vector);
    if (score !== undefined) return { cvss: score, label: scoreToLabel(score) };
  }
  const label = databaseLabel !== undefined ? TEXT_LABELS[databaseLabel.toUpperCase()] : undefined;
  if (label !== undefined) {
    const representative: Record<SeverityLabel, number> = {
      LOW: 2.0,
      MEDIUM: 5.5,
      HIGH: 8.0,
      CRITICAL: 9.5,
    };
    return { cvss: representative[label], label };
  }
  return { cvss: 5.5, label: 'MEDIUM' };
}
