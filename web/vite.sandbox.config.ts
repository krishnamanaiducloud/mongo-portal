import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

// Builds the mongosh sandbox as classic (IIFE) scripts:
//   --mode bootstrap  dist/shell-sandbox/bootstrap.js  (sandbox page; starts the worker)
//   --mode worker     dist/shell-sandbox/worker.js     (mongosh runtime)
// Classic scripts avoid the CORS requirement module scripts have when loaded
// from the sandbox's opaque origin. Node built-ins used by the mongosh
// packages are mapped to browser implementations or stubs.
const src = (f: string) => fileURLToPath(new URL(`./src/sandbox/${f}`, import.meta.url));

export default defineConfig(({ mode }) => {
  const entry = mode === 'bootstrap' ? 'bootstrap' : 'worker';
  return {
    define: {
      'process.env.NODE_ENV': JSON.stringify('production'),
    },
    resolve: {
      alias: {
        path: 'path-browserify',
        assert: 'assert',
        util: 'util',
        events: 'events',
        buffer: 'buffer',
        crypto: src('shims/crypto.ts'),
        fs: src('shims/empty.ts'),
        v8: src('shims/empty.ts'),
        '@mongodb-js/mongodb-ts-autocomplete': src('shims/ts-autocomplete.ts'),
      },
    },
    build: {
      outDir: 'dist/shell-sandbox',
      emptyOutDir: false,
      sourcemap: false,
      chunkSizeWarningLimit: 16000,
      lib: {
        entry: src(`${entry}.ts`),
        name: entry === 'worker' ? 'PortalShellWorker' : 'PortalShellBootstrap',
        formats: ['iife'],
        fileName: () => `${entry}.js`,
      },
    },
  };
});
