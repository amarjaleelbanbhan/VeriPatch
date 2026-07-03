import { NpmLockfileParser } from '../../src/adapters/lockfile/index.js';
import { YarnLockfileParser } from '../../src/adapters/lockfile/yarn/index.js';
import { runLockfileParserContract } from './lockfile-parser.contract.js';

runLockfileParserContract('NpmLockfileParser', () => new NpmLockfileParser(), {
  valid: 'v3-nested',
  hostile: ['corrupt', 'hostile-name', 'v1-legacy'],
  degraded: 'degraded-project',
});

runLockfileParserContract('YarnLockfileParser', () => new YarnLockfileParser(), {
  valid: 'yarn-classic-simple',
  hostile: ['yarn-corrupt', 'yarn-hostile-name'],
  degraded: 'degraded-project',
});
