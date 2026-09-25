import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': process.env.MILVAGO_API_TARGET ?? 'http://127.0.0.1:8080', '/auth': process.env.MILVAGO_API_TARGET ?? 'http://127.0.0.1:8080' } },
  // The image build runs this suite next to the Go and Rust builds; the 5 s default
  // timed out there on tests that take well under a second on an idle machine.
  test: { environment: 'jsdom', setupFiles: './src/test-setup.ts', restoreMocks: true, testTimeout: 20_000 },
});
