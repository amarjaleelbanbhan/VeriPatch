import fs from 'node:fs';
import { ScanOutputSchema, type ScanOutput } from '../../core/models/index.js';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';

/**
 * Evidence report, JSON form (blueprint §5.2, schemaVersion 1). Re-validates
 * against the schema before writing — a report that doesn't match its own
 * declared shape must never reach disk.
 */
export function writeJsonReport(scan: ScanOutput, filePath: string): Result<void> {
  const validated = ScanOutputSchema.safeParse(scan);
  if (!validated.success) {
    return err(
      AppError.internal(
        'REPORT_SCHEMA_INVALID',
        `Refusing to write a report.json that fails its own schema: ${validated.error.issues[0]?.message ?? 'invalid'}`,
      ),
    );
  }
  try {
    fs.writeFileSync(filePath, JSON.stringify(validated.data, null, 2));
    return ok(undefined);
  } catch (cause) {
    return err(
      AppError.world('REPORT_WRITE_FAILED', `Could not write ${filePath}`, undefined, cause),
    );
  }
}
