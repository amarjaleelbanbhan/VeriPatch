import { describe, expect, it } from 'vitest';
import { parseBerryLockfile } from '../../../../src/adapters/lockfile/yarn/berry.js';
import { parseClassicLockfile } from '../../../../src/adapters/lockfile/yarn/classic.js';
import {
  hasForeignProtocol,
  splitDescriptor,
  stripNpmProtocol,
} from '../../../../src/adapters/lockfile/yarn/entries.js';

describe('splitDescriptor', () => {
  it('splits bare and scoped descriptors at the last @', () => {
    expect(splitDescriptor('lodash@^4.17.20')).toEqual({ name: 'lodash', range: '^4.17.20' });
    expect(splitDescriptor('@scope/util@npm:^3.0.0')).toEqual({
      name: '@scope/util',
      range: '^3.0.0',
    });
  });

  it('rejects shapes that cannot be honest descriptors', () => {
    expect(splitDescriptor('no-separator')).toBeUndefined();
    expect(splitDescriptor('@scope/only-name')).toBeUndefined();
    expect(splitDescriptor('@^1.0.0')).toBeUndefined();
    expect(splitDescriptor('trailing@')).toBeUndefined();
  });
});

describe('protocol helpers', () => {
  it('strips only the npm protocol', () => {
    expect(stripNpmProtocol('npm:^1.0.0')).toBe('^1.0.0');
    expect(stripNpmProtocol('^1.0.0')).toBe('^1.0.0');
  });

  it('flags non-npm protocols as foreign', () => {
    for (const range of ['workspace:.', 'patch:app@npm%3A1.0.0#patch', 'file:../local']) {
      expect(hasForeignProtocol(range), range).toBe(true);
    }
    expect(hasForeignProtocol('npm:^1.0.0')).toBe(false);
    expect(hasForeignProtocol('^1.0.0')).toBe(false);
  });
});

describe('parseClassicLockfile', () => {
  it('parses CRLF files and multi-descriptor headers', () => {
    const raw = ['"a@^1.0.0", "a@^1.1.0":', '  version "1.2.3"', ''].join('\r\n');
    const r = parseClassicLockfile(raw);
    if (!r.ok) throw r.error;
    expect(r.value.get('a@^1.0.0')?.version).toBe('1.2.3');
    expect(r.value.get('a@^1.1.0')?.version).toBe('1.2.3');
  });

  it('handles quoted scoped dependency names in sections', () => {
    const raw = [
      'a@^1.0.0:',
      '  version "1.0.0"',
      '  dependencies:',
      '    "@scope/b" "^2.0.0"',
    ].join('\n');
    const r = parseClassicLockfile(raw);
    if (!r.ok) throw r.error;
    expect(r.value.get('a@^1.0.0')?.dependencies).toEqual({ '@scope/b': '^2.0.0' });
  });

  it('drops dependencies with foreign protocols', () => {
    const raw = [
      'a@^1.0.0:',
      '  version "1.0.0"',
      '  dependencies:',
      '    local "file:../elsewhere"',
      '    real "^2.0.0"',
    ].join('\n');
    const r = parseClassicLockfile(raw);
    if (!r.ok) throw r.error;
    expect(r.value.get('a@^1.0.0')?.dependencies).toEqual({ real: '^2.0.0' });
  });

  it('rejects an entry without a version', () => {
    const r = parseClassicLockfile(['a@^1.0.0:', '  integrity sha512-x'].join('\n'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toContain('no version');
  });

  it('rejects indented content before any header', () => {
    const r = parseClassicLockfile('  version "1.0.0"');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('LOCKFILE_INVALID');
  });

  it('rejects a dependency item outside a section', () => {
    const r = parseClassicLockfile(['a@^1.0.0:', '    b "^2.0.0"'].join('\n'));
    expect(r.ok).toBe(false);
  });

  it('reports the failing line number', () => {
    const r = parseClassicLockfile(['a@^1.0.0:', '  version "1.0.0"', 'not a header'].join('\n'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toContain('line 3');
  });
});

describe('parseBerryLockfile', () => {
  const metadata = ['__metadata:', '  version: 8', '  cacheKey: 10c0', ''].join('\n');

  it('requires a readable __metadata.version', () => {
    const r = parseBerryLockfile('"a@npm:^1.0.0":\n  version: 1.0.0\n');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toContain('__metadata');
  });

  it('skips workspace and patch descriptors entirely', () => {
    const raw =
      metadata +
      [
        '"me@workspace:.":',
        '  version: 0.0.0-use.local',
        '  resolution: "me@workspace:."',
        '',
        '"a@npm:^1.0.0":',
        '  version: 1.0.0',
        '  resolution: "a@npm:1.0.0"',
      ].join('\n');
    const r = parseBerryLockfile(raw);
    if (!r.ok) throw r.error;
    expect([...r.value.entries.keys()]).toEqual(['a@^1.0.0']);
    expect(r.value.metadataVersion).toBe(8);
  });

  it('stringifies YAML-numeric versions', () => {
    const raw = metadata + ['"a@npm:^2.0.0":', '  version: 2.5', ''].join('\n');
    const r = parseBerryLockfile(raw);
    if (!r.ok) throw r.error;
    expect(r.value.entries.get('a@^2.0.0')?.version).toBe('2.5');
  });

  it('rejects invalid YAML as a UserError', () => {
    const r = parseBerryLockfile('__metadata:\n  version: 8\n"a@npm:^1":\n  version: [1.0.0');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.kind).toBe('UserError');
      expect(r.error.code).toBe('LOCKFILE_INVALID');
    }
  });
});
