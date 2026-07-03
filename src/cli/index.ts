/**
 * VeriPatch CLI entry point.
 *
 * Layering rule (eslint-enforced): cli → services → core ← adapters.
 * This layer owns argument parsing, rendering, and exit codes only.
 */
export function main(): void {
  // Bootstrapped in M5 (scan command). Placeholder keeps the build honest.
  process.exitCode = 0;
}

main();
