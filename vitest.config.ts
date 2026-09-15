import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    setupFiles: ['./vitest.setup.ts'],
    environment: 'node',
    clearMocks: true // Auto clear mocks after every 'it'
  },
  define: {
    __DEV__: true,
  },
});
