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

  it('prefers npm when both lockfiles exist, and reports the loser', () => {
    const detected = detectLockfile(
      makeProject(['package-lock.json', 'yarn.lock', 'package.json']),
    );
    expect(detected.packageManager).toBe('npm');
    expect(detected.ignored).toEqual(['yarn.lock']);
  });

  it('falls back to the degraded npm parser with no lockfile at all', () => {
    const detected = detectLockfile(makeProject(['package.json']));
    expect(detected.packageManager).toBeNull();
    expect(detected.ignored).toEqual([]);
  });
});
