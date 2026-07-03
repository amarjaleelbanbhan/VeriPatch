// @ts-check
import { defineConfig } from 'eslint/config';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import boundaries from 'eslint-plugin-boundaries';
import prettierConfig from 'eslint-config-prettier';

export default defineConfig(
  {
    ignores: ['dist/', 'coverage/', 'node_modules/', '.veripatch/'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['*.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // A swallowed rejection can silently corrupt a verification verdict.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      'no-console': 'error',
    },
  },
  {
    // Layer boundaries: cli → services → core ← adapters (core is pure, imports nothing but shared)
    files: ['src/**/*.ts'],
    plugins: { boundaries },
    settings: {
      'import/resolver': {
        typescript: { alwaysTryTypes: true },
      },
      'boundaries/elements': [
        { type: 'cli', pattern: 'src/cli' },
        { type: 'services', pattern: 'src/services' },
        { type: 'core', pattern: 'src/core' },
        { type: 'adapters', pattern: 'src/adapters' },
        { type: 'shared', pattern: 'src/shared' },
      ],
    },
    rules: {
      'boundaries/element-types': [
        'error',
        {
          default: 'disallow',
          rules: [
            { from: 'cli', allow: ['cli', 'services', 'core', 'shared', 'adapters'] },
            { from: 'services', allow: ['services', 'core', 'shared'] },
            { from: 'core', allow: ['core', 'shared'] },
            { from: 'adapters', allow: ['adapters', 'core', 'shared'] },
            { from: 'shared', allow: ['shared'] },
          ],
        },
      ],
    },
  },
  {
    // core/ must stay pure: no filesystem, network, child processes, or Docker.
    files: ['src/core/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'fs', message: 'core/ is pure — do I/O in adapters/.' },
            { name: 'node:fs', message: 'core/ is pure — do I/O in adapters/.' },
            { name: 'fs/promises', message: 'core/ is pure — do I/O in adapters/.' },
            { name: 'node:fs/promises', message: 'core/ is pure — do I/O in adapters/.' },
            { name: 'child_process', message: 'core/ is pure — no process spawning.' },
            { name: 'node:child_process', message: 'core/ is pure — no process spawning.' },
            { name: 'http', message: 'core/ is pure — do network in adapters/.' },
            { name: 'node:http', message: 'core/ is pure — do network in adapters/.' },
            { name: 'https', message: 'core/ is pure — do network in adapters/.' },
            { name: 'node:https', message: 'core/ is pure — do network in adapters/.' },
            { name: 'dockerode', message: 'core/ is pure — Docker lives in adapters/sandbox.' },
          ],
        },
      ],
    },
  },
  {
    files: ['tests/**/*.ts', '*.config.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  {
    files: ['**/*.js'],
    extends: [tseslint.configs.disableTypeChecked],
  },
  prettierConfig,
);
