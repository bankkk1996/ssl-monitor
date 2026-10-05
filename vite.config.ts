import path from 'node:path';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  // `npm run dev` serves the UI; API calls go to `wrangler dev` on 8789.
  server: { proxy: { '/api': 'http://localhost:8789' } },
});
