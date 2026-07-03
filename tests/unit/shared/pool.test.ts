import { describe, expect, it } from 'vitest';
import { mapWithConcurrency } from '../../../src/shared/pool.js';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('mapWithConcurrency', () => {
  it('preserves input order even when later items finish first', async () => {
    const results = await mapWithConcurrency([30, 5, 15], 3, async (delay) => {
      await sleep(delay);
      return delay;
    });
    expect(results).toEqual([30, 5, 15]);
  });

  it('never exceeds the concurrency limit', async () => {
    let inFlight = 0;
    let peak = 0;
    await mapWithConcurrency(
      Array.from({ length: 10 }, (_, i) => i),
      3,
      async () => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await sleep(5);
        inFlight--;
      },
    );
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1); // it did actually parallelize
  });

  it('runs serially with limit 1', async () => {
    const order: number[] = [];
    await mapWithConcurrency([2, 1, 0], 1, async (item) => {
      order.push(item);
      await sleep(1);
    });
    expect(order).toEqual([2, 1, 0]);
  });

  it('propagates rejections', async () => {
    await expect(
      mapWithConcurrency([1, 2], 2, (item) =>
        item === 2 ? Promise.reject(new Error('boom')) : Promise.resolve(item),
      ),
    ).rejects.toThrow('boom');
  });

  it('handles an empty input', async () => {
    expect(await mapWithConcurrency([], 4, () => Promise.resolve(1))).toEqual([]);
  });
});
