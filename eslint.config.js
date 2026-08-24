import js from '@eslint/js';
import globals from 'globals';
import prettier from 'eslint-config-prettier';

export default [
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      eqeqeq: ['error', 'smart'],
      'no-console': 'off', // the CLI prints to stdout/stderr by design
      // Swallowed errors are deliberate: a malformed credentials file or a failed
      // log write must never take the proxy down.
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
  prettier, // must stay last: turns off rules that would fight the formatter
];
