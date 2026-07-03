import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readJsonFile, stripDangerousKeys } from '../../../../src/adapters/lockfile/safe-read.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-saferead-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('readJsonFile', () => {
  it('reads valid JSON', () => {
    const file = path.join(tmpDir, 'ok.json');
    fs.writeFileSync(file, '{"a": 1}');
    const r = readJsonFile(file);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toEqual({ a: 1 });
  });

  it('rejects missing files as UserError', () => {
    const r = readJsonFile(path.join(tmpDir, 'nope.json'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('FILE_NOT_FOUND');
  });

  it('rejects oversized files before reading them (size-limit test)', () => {
    const file = path.join(tmpDir, 'huge.json');
    // Sparse-ish: single write of 51MB of spaces — cheap to create, must be
    // rejected on stat() alone.
    fs.writeFileSync(file, Buffer.alloc(51 * 1024 * 1024, 0x20));
    const r = readJsonFile(file);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('FILE_TOO_LARGE');
  });

  it('rejects malformed JSON as UserError', () => {
    const file = path.join(tmpDir, 'bad.json');
    fs.writeFileSync(file, '{ nope');
    const r = readJsonFile(file);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('JSON_MALFORMED');
      expect(r.error.kind).toBe('UserError');
    }
  });

  it('strips __proto__ keys so later spreads cannot pollute', () => {
    const file = path.join(tmpDir, 'proto.json');
    fs.writeFileSync(file, '{"__proto__": {"polluted": true}, "safe": 1}');
    const r = readJsonFile(file);
    if (!r.ok) throw r.error;
    const copied = { ...(r.value as Record<string, unknown>) };
    expect(Object.keys(copied)).toEqual(['safe']);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});

describe('stripDangerousKeys', () => {
  it('removes __proto__, constructor, prototype recursively', () => {
    const hostile = JSON.parse(
      '{"a": {"__proto__": 1, "constructor": 2, "prototype": 3, "keep": 4}, "list": [{"__proto__": 5}]}',
    ) as unknown;
    expect(stripDangerousKeys(hostile)).toEqual({ a: { keep: 4 }, list: [{}] });
  });

  it('passes primitives through', () => {
    expect(stripDangerousKeys('x')).toBe('x');
    expect(stripDangerousKeys(1)).toBe(1);
    expect(stripDangerousKeys(null)).toBeNull();
  });
});
