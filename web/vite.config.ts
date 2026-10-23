import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// The production bundle is embedded into the Go binary. In development the
// API is proxied to a locally running portal backend.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 2000,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/oauth': 'http://127.0.0.1:8080',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
