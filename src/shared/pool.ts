/**
 * Bounded-concurrency map. Runs `fn` over `items` with at most `limit`
 * in flight; the result array preserves input order regardless of
 * completion order. Rejections are not swallowed — the first rejection
 * propagates after in-flight work settles, matching Promise.all semantics
 * closely enough for callers that already wrap failures in Result values.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const effectiveLimit = Math.max(1, Math.min(limit, items.length));
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  const workers = Array.from({ length: effectiveLimit }, async () => {
    for (;;) {
      const index = nextIndex++;
      if (index >= items.length) return;
      results[index] = await fn(items[index] as T, index);
    }
  });

  await Promise.all(workers);
  return results;
}
