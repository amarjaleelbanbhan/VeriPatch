import { describe, expect, it } from 'vitest';
import {
  box,
  explainStep,
  keyValueBlock,
  padEndVisible,
  resolveUiOptions,
  rule,
  table,
  terminalWidth,
  truncateVisible,
  visibleWidth,
  type UiOptions,
} from '../../../../src/cli/ui/index.js';

const ESC = String.fromCharCode(27);
const red = (text: string): string => `${ESC}[31m${text}${ESC}[0m`;

function ui(overrides: Partial<UiOptions> = {}): UiOptions {
  return { color: false, unicode: true, width: 40, ...overrides };
}

describe('visibleWidth / padEndVisible', () => {
  it('measures colored text by its visible characters, not raw length', () => {
    expect(visibleWidth(red('HIGH'))).toBe(4);
    expect(visibleWidth('HIGH')).toBe(4);
  });

  it('pads a colored cell to the same visible width as a plain one (regression: the previous table renderer under-padded colored cells)', () => {
    const plain = padEndVisible('LOW', 6);
    const colored = padEndVisible(red('LOW'), 6);
    expect(visibleWidth(plain)).toBe(6);
    expect(visibleWidth(colored)).toBe(6);
  });
});

describe('truncateVisible', () => {
  it('leaves short text untouched', () => {
    expect(truncateVisible('axios', 10)).toBe('axios');
  });

  it('regression: preserves color when the text already fits — every table/box cell passes through here on every render, so this is the overwhelmingly common case', () => {
    const cell = red('HIGH');
    expect(truncateVisible(cell, 10)).toBe(cell);
    expect(truncateVisible(cell, 10)).toContain(ESC);
  });

  it('truncates long text with an ellipsis', () => {
    expect(truncateVisible('a-very-long-package-name', 10)).toBe('a-very-lo…');
  });

  it('strips color rather than risk cutting an escape sequence in half', () => {
    const out = truncateVisible(red('a-very-long-package-name'), 10);
    expect(out).not.toContain(ESC);
    expect(out).toBe('a-very-lo…');
  });
});

describe('table', () => {
  it('aligns columns by visible width even when one column is colored', () => {
    const rows = table(
      [
        { name: 'axios', sev: red('HIGH') },
        { name: 'lodash-utils', sev: 'LOW' },
      ],
      [
        { header: 'PKG', cell: (r: { name: string }) => r.name },
        { header: 'SEV', cell: (r: { sev: string }) => r.sev },
      ],
      ui({ width: 80 }),
    );
    // every data row plus the header/separator should share one visible width
    const widths = new Set(rows.map((line) => visibleWidth(line)));
    expect(widths.size).toBe(1);
  });

  it('shrinks and truncates the widest column instead of overflowing the terminal', () => {
    const rows = table(
      [{ id: 'GHSA-extremely-long-advisory-identifier-that-is-huge', note: 'x' }],
      [
        { header: 'ID', cell: (r: { id: string }) => r.id },
        { header: 'NOTE', cell: (r: { note: string }) => r.note },
      ],
      ui({ width: 30 }),
    );
    for (const line of rows) expect(visibleWidth(line)).toBeLessThanOrEqual(30);
  });
});

describe('box', () => {
  it('produces a closed rounded border with padded, equal-width content lines', () => {
    const lines = box(['short', 'a bit longer'], ui({ width: 40 }));
    expect(lines[0]).toMatch(/^╭─+╮$/);
    expect(lines.at(-1)).toMatch(/^╰─+╯$/);
    const widths = new Set(lines.map((l) => visibleWidth(l)));
    expect(widths.size).toBe(1);
  });

  it('falls back to plain ASCII corners when unicode is unsupported', () => {
    const lines = box(['hi'], ui({ unicode: false, width: 40 }));
    expect(lines[0]?.startsWith('+')).toBe(true);
    expect(lines.at(-1)?.endsWith('+')).toBe(true);
  });
});

describe('keyValueBlock', () => {
  it('starts every value at the same column, regardless of label length', () => {
    const lines = keyValueBlock([
      ['Short', 'VALUE_ONE'],
      ['Much longer label', 'VALUE_TWO'],
    ]);
    expect(lines[0]?.indexOf('VALUE_ONE')).toBe(lines[1]?.indexOf('VALUE_TWO'));
  });
});

describe('rule / terminalWidth', () => {
  it('caps width to keep ultrawide terminals from stretching content', () => {
    const stream = { columns: 400 } as unknown as NodeJS.WritableStream;
    expect(terminalWidth(stream)).toBeLessThanOrEqual(76);
  });

  it('falls back to 80 columns when width is unknown, then applies the cap', () => {
    const stream = {} as NodeJS.WritableStream;
    expect(terminalWidth(stream)).toBe(76);
  });

  it('draws a rule exactly options.width characters wide', () => {
    expect(rule(ui({ width: 20 })).length).toBe(20);
  });
});

describe('resolveUiOptions', () => {
  it('carries the resolved color flag through unchanged', () => {
    expect(resolveUiOptions(true).color).toBe(true);
    expect(resolveUiOptions(false).color).toBe(false);
  });
});

describe('explainStep', () => {
  it('glosses the steps that mean something to a non-expert reviewer', () => {
    expect(explainStep('rescan')).toBe('Upgrade verified');
    expect(explainStep('build')).toBe('Build succeeded');
    expect(explainStep('test')).toBe('Tests passed');
  });

  it('falls back to the raw step name for anything it does not have a gloss for', () => {
    expect(explainStep('copy')).toBe('copy');
  });
});
