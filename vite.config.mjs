import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'web',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The server's CSP forbids inline scripts, so nothing may be inlined.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8081', '/ws': { target: 'ws://127.0.0.1:8081', ws: true } },
  },
});
