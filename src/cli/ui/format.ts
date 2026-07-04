import { stripAnsi } from '../../shared/sanitize.js';
import { getSymbols, supportsUnicode } from './symbols.js';

/**
 * Layout primitives shared by every command's human-readable output. The
 * single rule that matters here: measure and pad by *visible* width, never
 * `string.length` — a colored cell's raw length includes invisible ANSI
 * bytes, so naive `.padEnd()` under-pads it and silently wrecks column
 * alignment the moment a severity badge gets a color. (The previous table
 * renderer had exactly this bug.)
 */

export function visibleWidth(text: string): number {
  return stripAnsi(text).length;
}

export function padEndVisible(text: string, width: number): string {
  const gap = width - visibleWidth(text);
  return gap > 0 ? text + ' '.repeat(gap) : text;
}

export function padStartVisible(text: string, width: number): string {
  const gap = width - visibleWidth(text);
  return gap > 0 ? ' '.repeat(gap) + text : text;
}

/**
 * Truncates by visible width. The overwhelmingly common case is that the
 * text already fits — every table cell and box line passes through here on
 * every render, so that case must return the original string untouched,
 * ANSI codes and all. Only once truncation is actually needed does it strip
 * color first, rather than risk slicing through the middle of an escape
 * sequence and corrupting the rest of the line.
 */
export function truncateVisible(text: string, maxWidth: number, ellipsis = '…'): string {
  if (visibleWidth(text) <= maxWidth) return text;
  const stripped = stripAnsi(text);
  if (maxWidth <= ellipsis.length) return stripped.slice(0, maxWidth);
  return stripped.slice(0, maxWidth - ellipsis.length) + ellipsis;
}

/**
 * Real terminal width, but capped. Auto-detecting is what lets this degrade
 * on a narrow CI log viewer or split-pane terminal; capping is what keeps a
 * 220-column ultrawide from stretching every table into something you can't
 * scan in five seconds. 76 is the same rough measure most docs/readme
 * renderers wrap prose to.
 */
export function terminalWidth(stream: NodeJS.WritableStream = process.stdout): number {
  const columns = (stream as { columns?: number }).columns;
  const detected = typeof columns === 'number' && columns > 0 ? columns : 80;
  return Math.max(48, Math.min(detected, 76));
}

export interface UiOptions {
  color: boolean;
  unicode: boolean;
  width: number;
}

/** Resolves every environment signal once per command invocation. */
export function resolveUiOptions(color: boolean): UiOptions {
  return { color, unicode: supportsUnicode(), width: terminalWidth() };
}

export function rule(options: UiOptions, char?: string): string {
  const sym = getSymbols(options.unicode);
  return (char ?? sym.line.h).repeat(options.width);
}

export interface Column<T> {
  header: string;
  align?: 'left' | 'right';
  cell: (row: T) => string;
}

/**
 * Renders an aligned table. Columns are sized from real content (no
 * hardcoded widths); if the total would overflow the terminal, the widest
 * column shrinks and its cells are truncated with an ellipsis rather than
 * wrapping — wrapping is what turns a table into a wall of text.
 */
export function table<T>(rows: T[], columns: Column<T>[], options: UiOptions): string[] {
  const cells = rows.map((row) => columns.map((c) => c.cell(row)));
  const gap = 2;

  let widths = columns.map((c, i) =>
    Math.max(visibleWidth(c.header), ...cells.map((r) => visibleWidth(r[i] ?? ''))),
  );

  const totalWidth = widths.reduce((a, b) => a + b, 0) + gap * (columns.length - 1);
  const overflow = totalWidth - options.width;
  if (overflow > 0) {
    const widestIndex = widths.indexOf(Math.max(...widths));
    widths = widths.map((w, i) => (i === widestIndex ? Math.max(8, w - overflow) : w));
  }

  const renderRow = (rawCells: string[], align: (i: number) => 'left' | 'right'): string =>
    rawCells
      .map((cell, i) => {
        const w = widths[i] ?? 0;
        const truncated = truncateVisible(cell, w);
        return align(i) === 'right' ? padStartVisible(truncated, w) : padEndVisible(truncated, w);
      })
      .join(' '.repeat(gap));

  const alignOf = (i: number): 'left' | 'right' => columns[i]?.align ?? 'left';
  const sepChar = getSymbols(options.unicode).line.h;
  const lines = [
    renderRow(
      columns.map((c) => c.header),
      () => 'left',
    ),
  ];
  lines.push(widths.map((w) => sepChar.repeat(w)).join(' '.repeat(gap)));
  for (const row of cells) lines.push(renderRow(row, alignOf));
  return lines;
}

/**
 * A bordered card for the moments that deserve emphasis (project summary,
 * final recommendation) — used sparingly. A box around every section is
 * noise; a box around the one thing you want someone to screenshot is
 * signal.
 */
export function box(lines: string[], options: UiOptions, opts: { title?: string } = {}): string[] {
  const sym = getSymbols(options.unicode);
  // Total width budget: 2 border chars + 2 spaces of padding on each side.
  const BORDER_AND_PADDING = 6;
  const innerWidth = Math.max(
    opts.title !== undefined ? visibleWidth(opts.title) + 2 : 0,
    ...lines.map(visibleWidth),
  );
  const width = Math.min(innerWidth + BORDER_AND_PADDING, options.width);
  const contentWidth = width - BORDER_AND_PADDING;

  const top = `${sym.corner.tl}${sym.line.h.repeat(width - 2)}${sym.corner.tr}`;
  const bottom = `${sym.corner.bl}${sym.line.h.repeat(width - 2)}${sym.corner.br}`;
  const pad = (line: string) =>
    `${sym.line.v}  ${padEndVisible(truncateVisible(line, contentWidth), contentWidth)}  ${sym.line.v}`;

  const out = [top];
  for (const line of lines) out.push(pad(line));
  out.push(bottom);
  return out;
}

/** Aligned "label   value" blocks — the project summary / key metrics list. */
export function keyValueBlock(pairs: [string, string][]): string[] {
  const labelWidth = Math.max(...pairs.map(([label]) => visibleWidth(label)));
  return pairs.map(([label, value]) => `${padEndVisible(label, labelWidth)}   ${value}`);
}

/**
 * Plain-language gloss for a passed verification step — shared by `scan`'s
 * verification section and `verify`'s live verdict so a reviewer sees the
 * same wording ("Upgrade verified", "Tests passed") in both places.
 */
export function explainStep(step: string): string {
  switch (step) {
    case 'rescan':
      return 'Upgrade verified';
    case 'build':
      return 'Build succeeded';
    case 'test':
      return 'Tests passed';
    default:
      return step;
  }
}
