import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Crypto unit tests run in Node (WebCrypto's crypto.subtle is a global).
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Playwright/axe specs live in e2e/ and must never be collected by vitest.
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
});
