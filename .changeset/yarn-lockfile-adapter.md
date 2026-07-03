---
'veripatch': minor
---

`scan` now supports yarn projects: both classic (v1) and berry (v2+) `yarn.lock` files are
parsed into the same dependency graph as npm lockfiles, with auto-detection when multiple
lockfiles coexist (`package-lock.json` wins, with a warning). Reports gain a `packageManager`
field. `verify` and `update` refuse yarn projects explicitly for now — they replay fixes with
npm, and silently writing a `package-lock.json` into a yarn project would corrupt it.
