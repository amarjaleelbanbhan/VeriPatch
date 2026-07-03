import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { NpmLockfileParser } from '../../src/adapters/lockfile/index.js';

const FIXTURES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'lockfiles',
);

const parser = new NpmLockfileParser();

describe('NpmLockfileParser on the fixture corpus', () => {
  it('v3: nested duplicates, dev flags, provenance paths, integrity', () => {
    const r = parser.parse(path.join(FIXTURES, 'v3-nested'));
    if (!r.ok) throw r.error;
    const g = r.value;

    expect(g.lockfileVersion).toBe(3);
    expect(g.degraded).toBe(false);
    expect(g.nodes.map((n) => `${n.name}@${n.version}`)).toEqual([
      'a@1.2.3',
      'b@1.0.0',
      'b@2.0.0',
      'd@1.0.0',
      'e@1.0.0',
    ]);

    const a = g.nodes.find((n) => n.name === 'a')!;
    expect(a).toMatchObject({ direct: true, dev: false, integrity: 'sha512-aaa' });
    expect(a.paths).toEqual([['root', 'a']]);

    // duplicate versions of b resolved to the right consumers
    const b1 = g.nodes.find((n) => n.name === 'b' && n.version === '1.0.0')!;
    const b2 = g.nodes.find((n) => n.name === 'b' && n.version === '2.0.0')!;
    expect(b1.direct).toBe(true);
    expect(b1.paths).toEqual([['root', 'b']]);
    expect(b2.direct).toBe(false);
    expect(b2.paths).toEqual([['root', 'a', 'b']]);

    // dev subtree flagged
    const e = g.nodes.find((n) => n.name === 'e')!;
    expect(e.dev).toBe(true);
    expect(e.direct).toBe(false);
    expect(e.paths).toEqual([['root', 'd', 'e']]);
  });

  it('v2: parses via the shared packages walker (scoped name)', () => {
    const r = parser.parse(path.join(FIXTURES, 'v2-simple'));
    if (!r.ok) throw r.error;
    expect(r.value.lockfileVersion).toBe(2);
    expect(r.value.nodes).toHaveLength(1);
    expect(r.value.nodes[0]).toMatchObject({
      name: '@scope/lib',
      version: '3.1.4',
      direct: true,
    });
  });

  it('v1: rejected with an upgrade hint', () => {
    const r = parser.parse(path.join(FIXTURES, 'v1-legacy'));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('LOCKFILE_UNSUPPORTED_VERSION');
      expect(r.error.hint).toContain('npm');
    }
  });

  it('corrupt: rejected as UserError, never a crash', () => {
    const r = parser.parse(path.join(FIXTURES, 'corrupt'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('JSON_MALFORMED');
  });

  it('hostile __proto__ keys: parsed safely without prototype pollution', () => {
    const r = parser.parse(path.join(FIXTURES, 'hostile-proto'));
    if (!r.ok) throw r.error;
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(r.value.nodes.map((n) => n.name)).toEqual(['safe-pkg']);
  });

  it('hostile package name: rejected as UserError', () => {
    const r = parser.parse(path.join(FIXTURES, 'hostile-name'));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('LOCKFILE_HOSTILE_ENTRY');
      expect(r.error.kind).toBe('UserError');
    }
  });

  it('degraded: package.json only, ranges pinned to minimum versions', () => {
    const r = parser.parse(path.join(FIXTURES, 'degraded-project'));
    if (!r.ok) throw r.error;
    const g = r.value;
    expect(g.degraded).toBe(true);
    expect(g.lockfileVersion).toBeNull();
    expect(g.nodes.map((n) => `${n.name}@${n.version}`).sort()).toEqual(['a@1.2.0', 'd@2.0.0']);
    expect(g.nodes.every((n) => n.direct)).toBe(true);
    const d = g.nodes.find((n) => n.name === 'd')!;
    expect(d.dev).toBe(true);
  });

  it('workspaces: members attribute paths but are never vulnerability nodes', () => {
    const r = parser.parse(path.join(FIXTURES, 'v3-workspaces'));
    if (!r.ok) throw r.error;
    const g = r.value;

    // only registry packages appear — @ws/app and @ws/lib are first-party
    expect(g.nodes.map((n) => `${n.name}@${n.version}`)).toEqual([
      'app-dev-dep@4.1.0',
      'lib-only-dep@3.0.1',
      'root-dep@1.5.0',
      'shared-dep@2.2.0',
    ]);

    // provenance chains pass through workspace names
    const libOnly = g.nodes.find((n) => n.name === 'lib-only-dep')!;
    expect(libOnly.paths).toContainEqual(['root', '@ws/lib', 'lib-only-dep']);
    // ...including cross-workspace hops (@ws/app depends on @ws/lib)
    expect(libOnly.paths).toContainEqual(['root', '@ws/app', '@ws/lib', 'lib-only-dep']);

    // declared in a workspace manifest → direct (fixable in that manifest)
    const shared = g.nodes.find((n) => n.name === 'shared-dep')!;
    expect(shared.direct).toBe(true);
    expect(shared.paths).toContainEqual(['root', '@ws/app', 'shared-dep']);

    // dev flag still comes from the lockfile entry
    const dev = g.nodes.find((n) => n.name === 'app-dev-dep')!;
    expect(dev.dev).toBe(true);

    const rootDep = g.nodes.find((n) => n.name === 'root-dep')!;
    expect(rootDep).toMatchObject({ direct: true, dev: false });
    expect(rootDep.paths).toEqual([['root', 'root-dep']]);
  });

  it('no project at all: NO_MANIFEST UserError', () => {
    const r = parser.parse(path.join(FIXTURES, 'does-not-exist'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('NO_MANIFEST');
  });
});
