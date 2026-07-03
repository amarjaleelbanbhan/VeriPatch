import { NpmLockfileParser } from '../../src/adapters/lockfile/index.js';
import { runLockfileParserContract } from './lockfile-parser.contract.js';

runLockfileParserContract('NpmLockfileParser', () => new NpmLockfileParser());
