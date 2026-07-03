/**
 * Boundary sanitization (blueprint §2/§9): every external string (advisory
 * text, log output, package metadata) is cleaned before it crosses into core
 * or a report. ANSI escapes enable terminal injection; raw control characters
 * corrupt output; Markdown escaping happens at render time in the reporter.
 */

// CSI/OSC and other ESC-introduced sequences (pattern follows the strip-ansi package).
const ANSI_PATTERN = [
  '[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*',
  '|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?(?:\\u0007|\\u001B\\u005C|\\u009C))',
  '|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-nq-uy=><~]))',
].join('');

// All C0/C1 control characters except \n and \t (and \r, normalized separately).
const CONTROL_PATTERN = '[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F]';

const MAX_EXTERNAL_STRING_LENGTH = 10_000;

export function stripAnsi(text: string): string {
  return text.replace(new RegExp(ANSI_PATTERN, 'g'), '');
}

/** Strip ANSI + control chars, normalize CRLF, cap length. Apply to every external string. */
export function sanitizeExternalString(text: string): string {
  const cleaned = stripAnsi(text)
    .replaceAll('\r\n', '\n')
    .replaceAll('\r', '\n')
    .replace(new RegExp(CONTROL_PATTERN, 'g'), '');
  return cleaned.length > MAX_EXTERNAL_STRING_LENGTH
    ? `${cleaned.slice(0, MAX_EXTERNAL_STRING_LENGTH)}… [truncated]`
    : cleaned;
}

/** Escape Markdown so external strings render as inert text. Used by the reporter. */
export function escapeMarkdown(text: string): string {
  return text.replace(/([\\`*_{}[\]()<>#+\-.!|~])/g, '\\$1');
}
