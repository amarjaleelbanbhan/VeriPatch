/**
 * Terminal design tokens (blueprint §6 CLI UX). Deliberately zero-dependency —
 * raw ANSI 16-color codes only, no chalk/ora/cli-table3. Those 16 colors are
 * what every terminal theme (light or dark) has already remapped to something
 * readable; reaching for 256-color/truecolor would look great on the author's
 * theme and wrong on everyone else's.
 */

const CODES = {
  reset: '[0m',
  bold: '[1m',
  dim: '[2m',
  black: '[30m',
  red: '[31m',
  green: '[32m',
  yellow: '[33m',
  blue: '[34m',
  magenta: '[35m',
  cyan: '[36m',
  white: '[37m',
  gray: '[90m',
} as const;
export type ColorName = keyof typeof CODES;

/**
 * Semantic palette, not raw colors — every call site says *why* (brand,
 * success, danger…), never *which ANSI code*. That's what keeps the palette
 * consistent across scan/verify/doctor instead of drifting file by file.
 */
export const TONE = {
  brand: 'cyan',
  success: 'green',
  warning: 'yellow',
  danger: 'red',
  muted: 'gray',
  info: 'blue',
} as const satisfies Record<string, ColorName>;
export type Tone = keyof typeof TONE;

export interface Paint {
  (text: string, tone: Tone): string;
  bold: (text: string) => string;
  dim: (text: string) => string;
  boldTone: (text: string, tone: Tone) => string;
  readonly enabled: boolean;
}

export function createPaint(enabled: boolean): Paint {
  const wrap = (text: string, code: string): string =>
    enabled ? `${code}${text}${CODES.reset}` : text;
  const paint = ((text: string, tone: Tone) => wrap(text, CODES[TONE[tone]])) as Paint;
  paint.bold = (text: string) => wrap(text, CODES.bold);
  paint.dim = (text: string) => wrap(text, CODES.dim);
  paint.boldTone = (text: string, tone: Tone) =>
    enabled ? `${CODES.bold}${CODES[TONE[tone]]}${text}${CODES.reset}` : text;
  Object.defineProperty(paint, 'enabled', { value: enabled });
  return paint;
}

/**
 * Resolves whether to emit color from every signal that matters, in the
 * order the ecosystem actually checks them — not just the --no-color flag:
 * 1. NO_COLOR (https://no-color.org) always wins if set to anything.
 * 2. FORCE_COLOR=1 always wins next — explicit opt-in (e.g. a CI step that
 *    pipes through a color-aware log viewer) beats the TTY heuristic.
 * 3. Otherwise: the --no-color flag, AND stdout must be a real terminal.
 *    Piping to a file or `| cat` should never leave raw escape codes in the
 *    output — that's exactly the "ugly log" failure mode this redesign
 *    exists to avoid.
 */
export function resolveColor(
  flagEnabled: boolean,
  stream: NodeJS.WritableStream = process.stdout,
): boolean {
  if (process.env['NO_COLOR'] !== undefined) return false;
  if (process.env['FORCE_COLOR'] === '1') return true;
  return flagEnabled && Boolean((stream as { isTTY?: boolean }).isTTY);
}
