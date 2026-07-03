import os from 'node:os';
import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createLogger, redactHomeDir } from '../../../src/shared/logger.js';

function captureLogger(verbose = false) {
  const lines: string[] = [];
  const sink = new Writable({
    write(chunk: Buffer, _enc, cb) {
      lines.push(chunk.toString());
      cb();
    },
  });
  return { logger: createLogger({ verbose, destination: sink }), lines };
}

describe('redactHomeDir', () => {
  it('replaces the home directory with ~ in both slash styles', () => {
    expect(redactHomeDir('C:\\Users\\alice\\project', 'C:\\Users\\alice')).toBe('~\\project');
    expect(redactHomeDir('C:/Users/alice/project', 'C:\\Users\\alice')).toBe('~/project');
    expect(redactHomeDir('/home/alice/app/file.ts', '/home/alice')).toBe('~/app/file.ts');
  });

  it('leaves unrelated paths untouched', () => {
    expect(redactHomeDir('/opt/tool', '/home/alice')).toBe('/opt/tool');
  });
});

describe('createLogger', () => {
  it('emits NDJSON', () => {
    const { logger, lines } = captureLogger();
    logger.info('hello');
    logger.flush();
    const parsed = JSON.parse(lines[0]!) as { msg: string; level: number };
    expect(parsed.msg).toBe('hello');
  });

  it('redacts the home directory from messages and fields', () => {
    const { logger, lines } = captureLogger();
    const home = os.homedir();
    logger.info({ file: `${home}/secrets.txt` }, `reading ${home}/secrets.txt`);
    logger.flush();
    const out = lines.join('');
    expect(out).not.toContain(home);
    expect(out).toContain('~');
  });

  it('redacts secret-looking keys', () => {
    const { logger, lines } = captureLogger();
    logger.info({ token: 'npm_abc123', nested: { password: 'hunter2' } }, 'auth');
    logger.flush();
    const out = lines.join('');
    expect(out).not.toContain('npm_abc123');
    expect(out).not.toContain('hunter2');
    expect(out).toContain('[redacted]');
  });

  it('gates debug behind verbose', () => {
    const quiet = captureLogger(false);
    quiet.logger.debug('hidden');
    quiet.logger.flush();
    expect(quiet.lines).toHaveLength(0);

    const loud = captureLogger(true);
    loud.logger.debug('visible');
    loud.logger.flush();
    expect(loud.lines.length).toBeGreaterThan(0);
  });
});
