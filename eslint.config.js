import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Global Ignores
  {
    ignores: [
      'build/',
      'android/',
      'ios/',
      'lib/',
      'plugin/build/',
      'node_modules/',
      'example/',
    ],
  },

  // Base Rules: Apply standard JS and TS checks globally
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // React Native Environment
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      globals: {
        __DEV__: 'readonly', // Expo/React Native global
        console: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
      },
    },
    rules: {
      // Add any specific React Native bridge rules here
      '@typescript-eslint/no-explicit-any': 'warn', // Helpful for bridging unknown native payloads
    },
  },

  // Node.js Environment
  {
    files: ['plugin/src/**/*.ts', 'app.plugin.js'],
    languageOptions: {
      globals: {
        require: 'readonly',
        module: 'readonly',
        process: 'readonly',
        __dirname: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-var-requires': 'off',
    },
  }
);