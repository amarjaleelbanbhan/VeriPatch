---
'veripatch': minor
---

Transitive-dependency fixes are now applied the way a human would commit them: both the verify
sandbox and `veripatch update` write an npm `overrides` entry and regenerate the lockfile,
instead of running `npm install pkg@to` — which would have added the package as a new root
dependency. Direct dependencies keep the plain versioned install.
