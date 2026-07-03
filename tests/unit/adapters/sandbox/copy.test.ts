import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanupStagedProject, stageProjectCopy } from '../../../../src/adapters/sandbox/copy.js';

let projectDir: string;
let staged: { stagingDir: string } | undefined;

beforeEach(() => {
  projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-copy-src-'));
  fs.writeFileSync(path.join(projectDir, 'package.json'), '{"name":"fixture"}');
  fs.writeFileSync(path.join(projectDir, '.env'), 'SECRET=hunter2');
  fs.writeFileSync(path.join(projectDir, '.env.local'), 'SECRET=hunter3');
  fs.mkdirSync(path.join(projectDir, 'node_modules', 'left-pad'), { recursive: true });
  fs.writeFileSync(path.join(projectDir, 'node_modules', 'left-pad', 'index.js'), '// stub');
  fs.mkdirSync(path.join(projectDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(projectDir, '.git', 'HEAD'), 'ref: refs/heads/main');
  fs.mkdirSync(path.join(projectDir, '.veripatch'), { recursive: true });
  fs.writeFileSync(path.join(projectDir, '.veripatch', 'last-scan.json'), '{}');
  fs.mkdirSync(path.join(projectDir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(projectDir, 'src', 'index.ts'), 'export {};');
});

afterEach(() => {
  fs.rmSync(projectDir, { recursive: true, force: true });
  if (staged !== undefined) cleanupStagedProject(staged);
  staged = undefined;
});

describe('stageProjectCopy', () => {
  it('copies real project files into an isolated staging directory', () => {
    const result = stageProjectCopy(projectDir);
    if (!result.ok) throw result.error;
    staged = result.value;

    expect(staged.stagingDir).not.toBe(projectDir);
    expect(fs.readFileSync(path.join(staged.stagingDir, 'package.json'), 'utf8')).toBe(
      '{"name":"fixture"}',
    );
    expect(fs.readFileSync(path.join(staged.stagingDir, 'src', 'index.ts'), 'utf8')).toBe(
      'export {};',
    );
  });

  it('excludes node_modules, .git, .veripatch, and .env* files (blueprint §9)', () => {
    const result = stageProjectCopy(projectDir);
    if (!result.ok) throw result.error;
    staged = result.value;

    expect(fs.existsSync(path.join(staged.stagingDir, 'node_modules'))).toBe(false);
    expect(fs.existsSync(path.join(staged.stagingDir, '.git'))).toBe(false);
    expect(fs.existsSync(path.join(staged.stagingDir, '.veripatch'))).toBe(false);
    expect(fs.existsSync(path.join(staged.stagingDir, '.env'))).toBe(false);
    expect(fs.existsSync(path.join(staged.stagingDir, '.env.local'))).toBe(false);
  });

  it('reports a WorldError instead of throwing for an unreadable source directory', () => {
    const result = stageProjectCopy(path.join(projectDir, 'does-not-exist'));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('WorldError');
  });
});

describe('cleanupStagedProject', () => {
  it('removes the staging directory entirely', () => {
    const result = stageProjectCopy(projectDir);
    if (!result.ok) throw result.error;
    cleanupStagedProject(result.value);
    expect(fs.existsSync(result.value.stagingDir)).toBe(false);
    staged = undefined;
  });
});
