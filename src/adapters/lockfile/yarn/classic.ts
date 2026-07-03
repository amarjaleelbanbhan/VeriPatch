import { AppError } from '../../../shared/errors.js';
import { err, ok, type Result } from '../../../shared/result.js';
import {
  hasForeignProtocol,
  splitDescriptor,
  stripNpmProtocol,
  type YarnEntries,
  type YarnEntry,
} from './entries.js';

/**
 * Parser for yarn classic (v1) lockfiles — a custom indentation-based format,
 * not YAML. The grammar is small and rigid:
 *
 *   "descriptor", "descriptor":     ← entry header, column 0, trailing ':'
 *     version "1.2.3"               ← 2-space scalar fields
 *     integrity sha512-...
 *     dependencies:                 ← 2-space section header
 *       name "range"                ← 4-space section items
 *
 * The file is attacker-controlled input: anything outside this grammar is a
 * hard UserError, never a guess.
 */

interface OpenEntry {
  descriptors: { name: string; range: string }[];
  version?: string;
  integrity?: string;
  dependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  section: 'dependencies' | 'optionalDependencies' | undefined;
}

export function parseClassicLockfile(raw: string): Result<YarnEntries> {
  const entries: YarnEntries = new Map();
  let open: OpenEntry | undefined;

  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.trim().length === 0 || line.trimStart().startsWith('#')) continue;

    if (!line.startsWith(' ')) {
      const closed = closeEntry(open, entries, i);
      if (!closed.ok) return closed;
      const header = parseHeader(line, i);
      if (!header.ok) return header;
      open = header.value;
      continue;
    }

    if (open === undefined) {
      return parseError(i, 'indented line before any entry header');
    }

    if (line.startsWith('    ')) {
      if (open.section === undefined) {
        return parseError(i, 'dependency item outside a dependencies section');
      }
      const item = parseSectionItem(line, i);
      if (!item.ok) return item;
      const { name, range } = item.value;
      if (!hasForeignProtocol(range)) {
        open[open.section][name] = stripNpmProtocol(range);
      }
      continue;
    }

    // 2-space level: scalar field or section header.
    open.section = undefined;
    const body = line.trim();
    if (body === 'dependencies:') {
      open.section = 'dependencies';
    } else if (body === 'optionalDependencies:') {
      open.section = 'optionalDependencies';
    } else {
      const scalar = parseScalar(body, i);
      if (!scalar.ok) return scalar;
      const { key, value } = scalar.value;
      if (key === 'version') open.version = value;
      if (key === 'integrity') open.integrity = value;
      // resolved / other fields: read and ignored by design
    }
  }

  const closed = closeEntry(open, entries, lines.length);
  if (!closed.ok) return closed;
  return ok(entries);
}

function closeEntry(open: OpenEntry | undefined, entries: YarnEntries, line: number): Result<null> {
  if (open === undefined) return ok(null);
  if (open.version === undefined) {
    return parseError(line, `entry "${open.descriptors[0]?.name ?? '?'}" has no version field`);
  }
  for (const { name, range } of open.descriptors) {
    const entry: YarnEntry = {
      name,
      version: open.version,
      ...(open.integrity !== undefined ? { integrity: open.integrity } : {}),
      dependencies: open.dependencies,
      optionalDependencies: open.optionalDependencies,
    };
    entries.set(`${name}@${range}`, entry);
  }
  return ok(null);
}

function parseHeader(line: string, i: number): Result<OpenEntry> {
  if (!line.endsWith(':')) return parseError(i, 'entry header does not end with ":"');
  const descriptors: OpenEntry['descriptors'] = [];
  for (const part of splitTopLevel(line.slice(0, -1))) {
    const unquoted = unquote(part.trim());
    const split = splitDescriptor(unquoted);
    if (split === undefined) return parseError(i, `unparseable descriptor "${unquoted}"`);
    descriptors.push(split);
  }
  if (descriptors.length === 0) return parseError(i, 'entry header lists no descriptors');
  return ok({ descriptors, dependencies: {}, optionalDependencies: {}, section: undefined });
}

function parseScalar(body: string, i: number): Result<{ key: string; value: string }> {
  const space = body.indexOf(' ');
  if (space === -1) return parseError(i, `field line "${body}" has no value`);
  const key = body.slice(0, space);
  const value = unquote(body.slice(space + 1).trim());
  if (key.length === 0 || value.length === 0) return parseError(i, `empty field on "${body}"`);
  return ok({ key, value });
}

function parseSectionItem(line: string, i: number): Result<{ name: string; range: string }> {
  const body = line.trim();
  // `name "range"` — name itself may be quoted (scoped packages).
  const match = /^(?:"([^"]+)"|(\S+))\s+"?([^"]+)"?$/.exec(body);
  const name = match?.[1] ?? match?.[2];
  const range = match?.[3];
  if (match === null || name === undefined || range === undefined) {
    return parseError(i, `unparseable dependency item "${body}"`);
  }
  return ok({ name, range });
}

/** Splits on commas that are outside double quotes. */
function splitTopLevel(text: string): string[] {
  const parts: string[] = [];
  let current = '';
  let inQuotes = false;
  for (const ch of text) {
    if (ch === '"') inQuotes = !inQuotes;
    if (ch === ',' && !inQuotes) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts.filter((p) => p.trim().length > 0);
}

function unquote(text: string): string {
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    return text.slice(1, -1);
  }
  return text;
}

function parseError(line: number, detail: string): Result<never> {
  return err(
    AppError.user(
      'LOCKFILE_INVALID',
      `yarn.lock line ${String(line + 1)}: ${detail}`,
      'Regenerate the lockfile with yarn install.',
    ),
  );
}
