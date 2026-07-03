---
'veripatch': patch
---

Fix a critical bug where the CLI silently did nothing (exit 0, no output) when invoked through a globally-installed npm symlink on Linux/macOS -- the vast majority of real installs. `veripatch scan`, `veripatch --version`, and every other command were affected. Windows was unaffected (npm generates a `.cmd` wrapper there instead of a symlink), which is why this went unnoticed until a real end-to-end test against the published package on a Linux CI runner.
