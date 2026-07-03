import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { YarnLockfileParser } from '../../src/adapters/lockfile/yarn/index.js';

const FIXTURES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'lockfiles',
);

const parser = new YarnLockfileParser();

describe('YarnLockfileParser on the fixture corpus', () => {
  it('classic v1: multi-descriptor entries, scoped names, dev reachability', () => {
    const r = parser.parse(path.join(FIXTURES, 'yarn-classic-simple'));
    if (!r.ok) throw r.error;
    const g = r.value;

    expect(g.packageManager).toBe('yarn');
    expect(g.lockfileVersion).toBe(1);
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

    // reachable both directly and through app-lib
    const scoped = g.nodes.find((n) => n.name === '@scope/util')!;
    expect(scoped.direct).toBe(true);
    expect(scoped.dev).toBe(false);
    expect(scoped.paths).toContainEqual(['root', '@scope/util']);
    expect(scoped.paths).toContainEqual(['root', 'app-lib', '@scope/util']);

    // deep-dep is needed by both a prod and a dev consumer → not dev-only
    const deep = g.nodes.find((n) => n.name === 'deep-dep')!;
    expect(deep.dev).toBe(false);
    expect(deep.direct).toBe(false);

    // dev-tool is only reachable from devDependencies
    const devTool = g.nodes.find((n) => n.name === 'dev-tool')!;
    expect(devTool.dev).toBe(true);
    expect(devTool.direct).toBe(true);
  });

  it('berry: __metadata version, npm protocol stripping, workspace entries skipped', () => {
    const r = parser.parse(path.join(FIXTURES, 'yarn-berry-nested'));
    if (!r.ok) throw r.error;
    const g = r.value;

    expect(g.packageManager).toBe('yarn');
    expect(g.lockfileVersion).toBe(8);
    // the workspace:. self-entry must not appear as a dependency node
    expect(g.nodes.map((n) => `${n.name}@${n.version}`)).toEqual([
      '@scope/util@3.1.4',
      'app-lib@1.2.3',
      'deep-dep@2.0.1',
      'dev-tool@2.5.0',
    ]);

    const appLib = g.nodes.find((n) => n.name === 'app-lib')!;
    expect(appLib).toMatchObject({ direct: true, dev: false, integrity: '10c0/appliphash' });

    const devTool = g.nodes.find((n) => n.name === 'dev-tool')!;
    expect(devTool.dev).toBe(true);
  });

  it('classic and berry agree on the same dependency tree', () => {
    const classic = parser.parse(path.join(FIXTURES, 'yarn-classic-simple'));
    const berry = parser.parse(path.join(FIXTURES, 'yarn-berry-nested'));
    if (!classic.ok) throw classic.error;
    if (!berry.ok) throw berry.error;
    const shape = (g: typeof classic.value) =>
      g.nodes.map(({ name, version, dev, direct, paths }) => ({
        name,
        version,
        dev,
        direct,
        paths,
      }));
    expect(shape(classic.value)).toEqual(shape(berry.value));
  });

  it('corrupt: rejected as UserError with a line number, never a crash', () => {
    const r = parser.parse(path.join(FIXTURES, 'yarn-corrupt'));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('LOCKFILE_INVALID');
      expect(r.error.kind).toBe('UserError');
    }
  });

  it('hostile package name: rejected as UserError', () => {
    const r = parser.parse(path.join(FIXTURES, 'yarn-hostile-name'));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('LOCKFILE_HOSTILE_ENTRY');
      expect(r.error.kind).toBe('UserError');
    }
  });

  it('yarn.lock without package.json: NO_MANIFEST UserError', () => {
    const r = parser.parse(path.join(FIXTURES, 'yarn-no-manifest'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('NO_MANIFEST');
  });

  it('no lockfile: falls back to degraded package.json parsing', () => {
    const r = parser.parse(path.join(FIXTURES, 'degraded-project'));
    if (!r.ok) throw r.error;
    expect(r.value.degraded).toBe(true);
    expect(r.value.packageManager).toBeNull();
  });
});
