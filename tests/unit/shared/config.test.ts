import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, loadConfig, RC_FILE_NAME } from '../../../src/shared/config.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-config-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeRc(content: unknown): void {
  fs.writeFileSync(
    path.join(tmpDir, RC_FILE_NAME),
    typeof content === 'string' ? content : JSON.stringify(content),
  );
}

describe('loadConfig precedence (defaults < rc < env < flags)', () => {
  it('returns defaults when nothing else is present', () => {
    const r = loadConfig({ cwd: tmpDir, env: {} });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.config).toEqual(DEFAULT_CONFIG);
      expect(r.value.warnings).toEqual([]);
      expect(r.value.rcPath).toBeUndefined();
    }
  });

  it('rc file overrides defaults', () => {
    writeRc({ severityThreshold: 'high', verifyTimeoutMin: 20 });
    const r = loadConfig({ cwd: tmpDir, env: {} });
    if (!r.ok) throw r.error;
    expect(r.value.config.severityThreshold).toBe('high');
    expect(r.value.config.verifyTimeoutMin).toBe(20);
    expect(r.value.config.includeDevDeps).toBe(true); // untouched default
  });

  it('env overrides rc', () => {
    writeRc({ severityThreshold: 'high' });
    const r = loadConfig({
      cwd: tmpDir,
      env: { VERIPATCH_SEVERITY_THRESHOLD: 'critical', VERIPATCH_INCLUDE_DEV_DEPS: 'false' },
    });
    if (!r.ok) throw r.error;
    expect(r.value.config.severityThreshold).toBe('critical');
    expect(r.value.config.includeDevDeps).toBe(false);
  });

  it('cli flags override everything', () => {
    writeRc({ severityThreshold: 'high' });
    const r = loadConfig({
      cwd: tmpDir,
      env: { VERIPATCH_SEVERITY_THRESHOLD: 'critical' },
      cliFlags: { severityThreshold: 'medium' },
    });
    if (!r.ok) throw r.error;
    expect(r.value.config.severityThreshold).toBe('medium');
  });

  it('coerces env numbers and comma lists', () => {
    const r = loadConfig({
      cwd: tmpDir,
      env: { VERIPATCH_CACHE_TTL_HOURS: '48', VERIPATCH_IGNORE: 'CVE-1, CVE-2' },
    });
    if (!r.ok) throw r.error;
    expect(r.value.config.cacheTtlHours).toBe(48);
    expect(r.value.config.ignore).toEqual(['CVE-1', 'CVE-2']);
  });
});

describe('loadConfig error handling', () => {
  it('invalid value → UserError naming the exact key', () => {
    writeRc({ severityThreshold: 'apocalyptic' });
    const r = loadConfig({ cwd: tmpDir, env: {} });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.kind).toBe('UserError');
      expect(r.error.code).toBe('CONFIG_INVALID');
      expect(r.error.message).toContain('severityThreshold');
    }
  });

  it('invalid env value → UserError naming the variable', () => {
    const r = loadConfig({ cwd: tmpDir, env: { VERIPATCH_VERIFY_TIMEOUT_MIN: 'soon' } });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.message).toContain('VERIPATCH_VERIFY_TIMEOUT_MIN');
  });

  it('unknown keys warn but do not fail', () => {
    writeRc({ severityThreshold: 'high', tpyo: true });
    const r = loadConfig({ cwd: tmpDir, env: {} });
    if (!r.ok) throw r.error;
    expect(r.value.warnings).toHaveLength(1);
    expect(r.value.warnings[0]).toContain('tpyo');
    expect(r.value.config.severityThreshold).toBe('high');
  });

  it('malformed JSON → UserError with hint', () => {
    writeRc('{ "severityThreshold": high, }');
    const r = loadConfig({ cwd: tmpDir, env: {} });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('CONFIG_MALFORMED');
      expect(r.error.hint).toBeDefined();
    }
  });

  it('non-object JSON → UserError', () => {
    writeRc('[1,2,3]');
    const r = loadConfig({ cwd: tmpDir, env: {} });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('CONFIG_MALFORMED');
  });

  it('explicit --config path that is missing → UserError (no silent fallback)', () => {
    const r = loadConfig({
      cwd: tmpDir,
      configPath: path.join(tmpDir, 'nope.json'),
      env: {},
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('CONFIG_NOT_FOUND');
  });
});
