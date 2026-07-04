---
'veripatch': patch
---

Fix a pnpm lockfile parsing bug: a package whose peer dependency itself has a peer suffix
(e.g. `@eslint-community/eslint-utils@4.9.1(eslint@9.39.4(jiti@1.21.7))` — extremely common in
real-world ESLint 9 projects) was rejected with "invalid npm package name". The parser used
`lastIndexOf('@')` on the raw lockfile key to split package name from version, which broke as
soon as the nested peer suffix contained its own `@`. It now strips the peer suffix first
(respecting nesting), then splits name from version.
