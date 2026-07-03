import { describe, expect, it } from 'vitest';
import { AppError } from '../../../src/shared/errors.js';
import { andThen, err, isErr, isOk, map, ok, unwrapOr } from '../../../src/shared/result.js';

describe('Result', () => {
  const boom = AppError.internal('BOOM', 'it broke');

  it('ok wraps a value', () => {
    const r = ok(42);
    expect(r.ok).toBe(true);
    expect(isOk(r)).toBe(true);
    expect(isErr(r)).toBe(false);
    if (r.ok) expect(r.value).toBe(42);
  });

  it('err wraps an error', () => {
    const r = err(boom);
    expect(r.ok).toBe(false);
    expect(isErr(r)).toBe(true);
    if (!r.ok) expect(r.error.code).toBe('BOOM');
  });

  it('map transforms success and passes errors through', () => {
    expect(map(ok(2), (n) => n * 2)).toEqual(ok(4));
    const e = err(boom);
    expect(map(e as never, (n: number) => n * 2)).toBe(e);
  });

  it('andThen chains fallible steps', () => {
    const half = (n: number) => (n % 2 === 0 ? ok(n / 2) : err(AppError.user('ODD', 'odd number')));
    expect(andThen(ok(4), half)).toEqual(ok(2));
    const failed = andThen(ok(3), half);
    expect(failed.ok).toBe(false);
    if (!failed.ok) expect(failed.error.code).toBe('ODD');
  });

  it('unwrapOr falls back only on error', () => {
    expect(unwrapOr(ok(1), 9)).toBe(1);
    expect(unwrapOr(err(boom), 9)).toBe(9);
  });
});

describe('AppError', () => {
  it('carries kind, code, message, hint', () => {
    const e = AppError.user('NO_LOCKFILE', 'no lockfile found', 'run npm install');
    expect(e.kind).toBe('UserError');
    expect(e.code).toBe('NO_LOCKFILE');
    expect(e.message).toBe('no lockfile found');
    expect(e.hint).toBe('run npm install');
    expect(e).toBeInstanceOf(Error);
  });

  it('world and internal factories set kinds', () => {
    expect(AppError.world('NET', 'network down').kind).toBe('WorldError');
    expect(AppError.internal('BUG', 'unexpected').kind).toBe('InternalError');
  });

  it('preserves cause for diagnostics', () => {
    const cause = new Error('ECONNRESET');
    const e = AppError.world('NET', 'network down', undefined, cause);
    expect(e.cause).toBe(cause);
  });
});
