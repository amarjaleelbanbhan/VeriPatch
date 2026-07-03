import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { PnpmLockfileParser } from '../../src/adapters/lockfile/pnpm/index.js';

const FIXTURES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'lockfiles',
);

const parser = new PnpmLockfileParser();

describe('PnpmLockfileParser on the fixture corpus', () => {
  it('v9: importers roots, snapshot edges, integrity from packages', () => {
    const r = parser.parse(path.join(FIXTURES, 'pnpm-v9-simple'));
    if (!r.ok) throw r.error;
    const g = r.value;

    expect(g.packageManager).toBe('pnpm');
    expect(g.lockfileVersion).toBe(9);
    expect(g.degraded).toBe(false);
    expect(g.nodes.map((n) => `${n.name}@${n.version}`)).toEqual([
      '@scope/util@3.1.4',
      'app-lib@1.2.3',
      'deep-dep@2.0.1',
      'dev-tool@2.5.0',
    ]);

    const appLib = g.nodes.find((n) => n.name === 'app-lib')!;
    expect(appLib).toMatchObject({ direct: true, dev: false, integrity: 'sha512-appliphash' });
    expect(appLib.paths).toEqual([['root', 'app-lib']]);

    const scoped = g.nodes.find((n) => n.name === '@scope/util')!;
    expect(scoped.direct).toBe(true);
    expect(scoped.paths).toContainEqual(['root', 'app-lib', '@scope/util']);

    const deep = g.nodes.find((n) => n.name === 'deep-dep')!;
    expect(deep.dev).toBe(false); // prod-reachable through app-lib
    expect(deep.direct).toBe(false);

    const devTool = g.nodes.find((n) => n.name === 'dev-tool')!;
    expect(devTool.dev).toBe(true);
    expect(devTool.direct).toBe(true);
  });

  it('v6: top-level roots, inline package edges, /-prefixed keys', () => {
    const r = parser.parse(path.join(FIXTURES, 'pnpm-v6-simple'));
    if (!r.ok) throw r.error;
    expect(r.value.lockfileVersion).toBe(6);
    expect(r.value.packageManager).toBe('pnpm');
  });

  it('v6 and v9 agree on the same dependency tree', () => {
    const v6 = parser.parse(path.join(FIXTURES, 'pnpm-v6-simple'));
    const v9 = parser.parse(path.join(FIXTURES, 'pnpm-v9-simple'));
    if (!v6.ok) throw v6.error;
    if (!v9.ok) throw v9.error;
    const shape = (g: typeof v6.value) =>
      g.nodes.map(({ name, version, dev, direct, paths, integrity }) => ({
        name,
        version,
        dev,
        direct,
        paths,
        integrity,
      }));
    expect(shape(v6.value)).toEqual(shape(v9.value));
  });

  it('corrupt YAML: rejected as UserError, never a crash', () => {
    const r = parser.parse(path.join(FIXTURES, 'pnpm-corrupt'));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('LOCKFILE_INVALID');
      expect(r.error.kind).toBe('UserError');
    }
  });

  it('hostile package name: rejected as UserError', () => {
    const r = parser.parse(path.join(FIXTURES, 'pnpm-hostile-name'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('LOCKFILE_HOSTILE_ENTRY');
  });

  it('no lockfile: falls back to degraded package.json parsing', () => {
    const r = parser.parse(path.join(FIXTURES, 'degraded-project'));
    if (!r.ok) throw r.error;
    expect(r.value.degraded).toBe(true);
    expect(r.value.packageManager).toBeNull();
  });
});
