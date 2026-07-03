import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { detectLockfile } from '../../../../src/adapters/lockfile/detect.js';

const tempDirs: string[] = [];

function makeProject(files: string[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-detect-'));
  tempDirs.push(dir);
  for (const file of files) fs.writeFileSync(path.join(dir, file), '');
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('detectLockfile', () => {
  it('picks npm for package-lock.json', () => {
    const detected = detectLockfile(makeProject(['package-lock.json', 'package.json']));
    expect(detected.packageManager).toBe('npm');
    expect(detected.ignored).toEqual([]);
  });

  it('picks yarn for yarn.lock', () => {
    const detected = detectLockfile(makeProject(['yarn.lock', 'package.json']));
    expect(detected.packageManager).toBe('yarn');
    expect(detected.ignored).toEqual([]);
  });

  it('picks pnpm for pnpm-lock.yaml', () => {
    const detected = detectLockfile(makeProject(['pnpm-lock.yaml', 'package.json']));
    expect(detected.packageManager).toBe('pnpm');
    expect(detected.ignored).toEqual([]);
  });

  it('prefers npm when several lockfiles exist, and reports the losers', () => {
    const detected = detectLockfile(
      makeProject(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'package.json']),
    );
    expect(detected.packageManager).toBe('npm');
    expect(detected.ignored).toEqual(['yarn.lock', 'pnpm-lock.yaml']);
  });

  it('prefers yarn over pnpm when npm is absent', () => {
    const detected = detectLockfile(makeProject(['yarn.lock', 'pnpm-lock.yaml', 'package.json']));
    expect(detected.packageManager).toBe('yarn');
    expect(detected.ignored).toEqual(['pnpm-lock.yaml']);
  });

  it('falls back to the degraded npm parser with no lockfile at all', () => {
    const detected = detectLockfile(makeProject(['package.json']));
    expect(detected.packageManager).toBeNull();
    expect(detected.ignored).toEqual([]);
  });
});
