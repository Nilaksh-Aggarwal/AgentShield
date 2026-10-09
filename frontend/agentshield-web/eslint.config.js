import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      // Type-aware rules: catch floating promises, unsafe `any` flows and misused async code.
      tseslint.configs.recommendedTypeChecked,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      // Direct fetch() is reserved for the central API client (src/services/api).
      'no-restricted-globals': [
        'error',
        { name: 'fetch', message: 'Use the central API client in src/services/api instead of fetch().' },
      ],
    },
  },
  {
    files: ['src/services/api/**/*.ts'],
    rules: {
      'no-restricted-globals': 'off',
    },
  },
])
