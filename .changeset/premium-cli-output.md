---
'veripatch': minor
---

Redesigned `veripatch scan` and `veripatch verify` terminal output to the polish level of
modern developer tools. `scan` now shows a brand header, a Project Summary card (package
manager, packages scanned, vulnerabilities, verified fixes, manual review), a ranked Top
Vulnerabilities table (package, severity, current version, safe version, verification status),
a Verification section that explains each real verdict in plain language, and a final
recommendation box. A progress spinner narrates the real scan phases. Everything is built on a
zero-dependency UI toolkit that measures by visible width (perfect alignment even with color),
auto-detects terminal width, degrades to ASCII where Unicode isn't supported, and emits zero
escape codes when piped to a file or a non-TTY (`NO_COLOR` / `FORCE_COLOR` honored). `--json`
output is unchanged.
