---
'veripatch': minor
---

`verify --all` can run sandbox verifications in parallel: new `verifyConcurrency` config key
(default 1, max 8) and `--concurrency` flag. Each verification keeps its own container,
network, and staging copy; per-candidate output is buffered and printed in input order, so the
transcript stays deterministic regardless of which sandbox finishes first.
