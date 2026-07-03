import { describe, expect, it } from 'vitest';
import { escapeMarkdown, sanitizeExternalString, stripAnsi } from '../../../src/shared/sanitize.js';

const ESC = '\u001B';
const BEL = '\u0007';

describe('stripAnsi', () => {
  it('removes color and cursor sequences', () => {
    expect(stripAnsi(`${ESC}[31mred${ESC}[0m`)).toBe('red');
    expect(stripAnsi(`${ESC}[2J${ESC}[Hclear`)).toBe('clear');
  });

  it('removes OSC hyperlink sequences', () => {
    expect(stripAnsi(`${ESC}]8;;https://evil.example${BEL}click me${ESC}]8;;${BEL}`)).toBe(
      'click me',
    );
  });

  it('leaves plain text alone', () => {
    expect(stripAnsi('just text')).toBe('just text');
  });
});

describe('sanitizeExternalString', () => {
  it('drops control characters but keeps newlines and tabs', () => {
    expect(sanitizeExternalString('a\u0000b\u0008c\nd\te')).toBe('abc\nd\te');
  });

  it('normalizes CRLF to LF', () => {
    expect(sanitizeExternalString('a\r\nb\rc')).toBe('a\nb\nc');
  });

  it('caps pathological lengths', () => {
    const out = sanitizeExternalString('x'.repeat(50_000));
    expect(out.length).toBeLessThan(11_000);
    expect(out.endsWith('[truncated]')).toBe(true);
  });

  it('neutralizes a terminal-injection package name end to end', () => {
    const hostile = `innocent${ESC}[8m${ESC}]0;pwned${BEL}`;
    expect(sanitizeExternalString(hostile)).toBe('innocent');
  });
});

describe('escapeMarkdown', () => {
  it('escapes markdown metacharacters', () => {
    expect(escapeMarkdown('*bold* [link](x) `code` | # <img>')).toBe(
      '\\*bold\\* \\[link\\]\\(x\\) \\`code\\` \\| \\# \\<img\\>',
    );
  });
});
