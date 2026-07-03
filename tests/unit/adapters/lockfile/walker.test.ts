import { describe, expect, it } from 'vitest';
import {
  deriveNameFromLocation,
  resolveDependency,
  walkPackages,
} from '../../../../src/adapters/lockfile/walker.js';
import type { RawLockfile } from '../../../../src/adapters/lockfile/schema.js';

function lock(packages: RawLockfile['packages']): RawLockfile {
  return { lockfileVersion: 3, packages };
}

describe('deriveNameFromLocation', () => {
  it('derives bare and scoped names', () => {
    expect(deriveNameFromLocation('node_modules/a')).toBe('a');
    expect(deriveNameFromLocation('node_modules/a/node_modules/@s/b')).toBe('@s/b');
  });

  it('rejects traversal and junk', () => {
    expect(deriveNameFromLocation('node_modules/..')).toBeUndefined();
    expect(deriveNameFromLocation('packages/foo')).toBeUndefined();
    expect(deriveNameFromLocation('node_modules/')).toBeUndefined();
  });
});

describe('resolveDependency', () => {
  const byLocation = new Map(
    ['node_modules/a', 'node_modules/b', 'node_modules/a/node_modules/b'].map((loc) => [
      loc,
      { location: loc, name: 'x', entry: {} },
    ]),
  );

  it('prefers the nearest nested copy', () => {
    expect(resolveDependency('node_modules/a', 'b', byLocation)).toBe(
      'node_modules/a/node_modules/b',
    );
  });

  it('walks up to the top level', () => {
    expect(resolveDependency('node_modules/b', 'a', byLocation)).toBe('node_modules/a');
  });

  it('returns undefined for unmet deps', () => {
    expect(resolveDependency('node_modules/a', 'ghost', byLocation)).toBeUndefined();
  });
});

describe('walkPackages', () => {
  it('errors on a lockfile without a root entry', () => {
    const r = walkPackages(lock({ 'node_modules/a': { version: '1.0.0' } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('LOCKFILE_NO_ROOT');
  });

  it('survives dependency cycles', () => {
    const r = walkPackages(
      lock({
        '': { dependencies: { a: '^1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { b: '^1.0.0' } },
        'node_modules/b': { version: '1.0.0', dependencies: { a: '^1.0.0' } },
      }),
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.map((n) => n.name).sort()).toEqual(['a', 'b']);
      const b = r.value.find((n) => n.name === 'b');
      expect(b?.paths).toEqual([['root', 'a', 'b']]);
    }
  });

  it('skips link entries and non-node_modules paths', () => {
    const r = walkPackages(
      lock({
        '': { dependencies: { a: '^1.0.0' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/linked': { link: true, version: '9.9.9' },
        'packages/workspace-pkg': { version: '1.0.0' },
      }),
    );
    if (!r.ok) throw r.error;
    expect(r.value.map((n) => n.name)).toEqual(['a']);
  });

  it('caps provenance paths per node', () => {
    // 12 direct deps all depending on shared → would be 12 chains; cap is 8.
    const packages: NonNullable<RawLockfile['packages']> = {
      '': {
        dependencies: Object.fromEntries([...Array(12).keys()].map((i) => [`p${String(i)}`, '*'])),
      },
      'node_modules/shared': { version: '1.0.0' },
    };
    for (let i = 0; i < 12; i++) {
      packages[`node_modules/p${String(i)}`] = {
        version: '1.0.0',
        dependencies: { shared: '*' },
      };
    }
    const r = walkPackages(lock(packages));
    if (!r.ok) throw r.error;
    const shared = r.value.find((n) => n.name === 'shared');
    expect(shared).toBeDefined();
    expect(shared!.paths.length).toBeLessThanOrEqual(8);
  });
});
