import { describe, expect, it } from 'vitest';
import { buildContainerCreateOptions } from '../../../../src/adapters/sandbox/docker.js';

/**
 * Asserts the hardening flags (blueprint §9) directly on the options object
 * handed to dockerode's createContainer — no daemon required. The security
 * e2e suite mirrors these same assertions via a live container `inspect()`.
 */
describe('buildContainerCreateOptions — hardening flags', () => {
  const options = buildContainerCreateOptions('node:20-slim', '/host/staging', 'veripatch-net-1');

  it('runs as a non-root user', () => {
    expect(options.User).toBe('1000:1000');
  });

  it('drops all Linux capabilities', () => {
    expect(options.HostConfig?.CapDrop).toEqual(['ALL']);
  });

  it('sets no-new-privileges', () => {
    expect(options.HostConfig?.SecurityOpt).toEqual(['no-new-privileges']);
  });

  it('caps pids, memory, and cpu', () => {
    expect(options.HostConfig?.PidsLimit).toBe(512);
    expect(options.HostConfig?.Memory).toBe(2 * 1024 * 1024 * 1024);
    expect(options.HostConfig?.NanoCpus).toBe(2_000_000_000);
  });

  it('mounts the staging copy, never a literal original-path bind by coincidence', () => {
    expect(options.HostConfig?.Binds).toEqual(['/host/staging:/workspace']);
    expect(options.WorkingDir).toBe('/workspace');
  });

  it('applies the requested network mode', () => {
    expect(options.HostConfig?.NetworkMode).toBe('veripatch-net-1');
    const isolated = buildContainerCreateOptions('node:20-slim', '/host/staging', 'none');
    expect(isolated.HostConfig?.NetworkMode).toBe('none');
  });

  it('keeps the container alive for exec rather than running a fixed command', () => {
    expect(options.Cmd).toEqual(['sleep', 'infinity']);
  });
});
