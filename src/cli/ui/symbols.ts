/**
 * Icon set with an ASCII fallback (blueprint §6 CLI UX: "gracefully degrade
 * if Unicode isn't supported"). Every call site asks for a *meaning*
 * ('pass', 'fail'…), never picks a glyph directly — that's what makes the
 * fallback table exhaustive instead of leaving some raw ✓ to slip through.
 */

export interface SymbolSet {
  pass: string;
  fail: string;
  warn: string;
  info: string;
  bullet: string;
  arrow: string;
  pending: string;
  brand: string;
  corner: { tl: string; tr: string; bl: string; br: string };
  line: { h: string; v: string };
  spinnerFrames: string[];
}

const UNICODE: SymbolSet = {
  pass: '✓',
  fail: '✗',
  warn: '⚠',
  info: 'ℹ',
  bullet: '›',
  arrow: '→',
  pending: '○',
  brand: '◆',
  corner: { tl: '╭', tr: '╮', bl: '╰', br: '╯' },
  line: { h: '─', v: '│' },
  spinnerFrames: ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
};

const ASCII: SymbolSet = {
  pass: '+',
  fail: 'x',
  warn: '!',
  info: 'i',
  bullet: '*',
  arrow: '->',
  pending: 'o',
  brand: '*',
  corner: { tl: '+', tr: '+', bl: '+', br: '+' },
  line: { h: '-', v: '|' },
  spinnerFrames: ['|', '/', '-', '\\'],
};

/**
 * Same heuristic the wider ecosystem (sindresorhus/is-unicode-supported,
 * used transitively by ora/listr2/inquirer) converged on: Unicode box-drawing
 * and Braille glyphs render reliably almost everywhere except legacy Windows
 * consoles that aren't Windows Terminal, ConEmu, or an editor-embedded
 * terminal (which all set one of the env vars below).
 */
export function supportsUnicode(env: NodeJS.ProcessEnv = process.env): boolean {
  if (process.platform !== 'win32') return true;
  return (
    env['WT_SESSION'] !== undefined ||
    env['TERMINUS_SUBLIME'] !== undefined ||
    env['ConEmuTask'] !== undefined ||
    env['TERM_PROGRAM'] === 'vscode' ||
    env['TERM'] === 'xterm-256color' ||
    env['CI'] !== undefined
  );
}

export function getSymbols(unicode: boolean): SymbolSet {
  return unicode ? UNICODE : ASCII;
}
