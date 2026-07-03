import { z } from 'zod';
import { AdvisorySchema } from './advisory.js';
import { DepNodeSchema } from './dep-graph.js';

/** A concrete match: this installed node is inside this advisory's affected range. */
export const VulnSchema = z.object({
  advisory: AdvisorySchema,
  node: DepNodeSchema,
  matchedRange: z.string(),
});
export type Vuln = z.infer<typeof VulnSchema>;
