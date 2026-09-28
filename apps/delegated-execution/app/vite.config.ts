// `defineConfig` from `vitest/config`, not from `vite` — vite's own
// `UserConfigExport` has no `test` key, so a `test` block under the vite import
// fails `tsc -b` with "Object literal may only specify known properties".
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Calimero Auth's mailbox allowlists ONE app origin (`app_origin` in its
      // config), and a dev server is not it — so a browser POST from
      // localhost:5173 is refused at the CORS preflight while curl succeeds.
      //
      // Proxying makes the request same-origin from the browser's side, which
      // sidesteps CORS entirely without touching a shared deployment. A real
      // requester app is added to the portal's allowlist instead; this exists so
      // enrolment can be exercised locally before anyone redeploys anything.
      //
      // Point the mailbox field at `http://localhost:5173/auth-mailbox` to use it.
      '/auth-mailbox': {
        target:
          process.env.AUTH_MAILBOX ??
          'https://calimero-mailbox-842788399636.europe-west1.run.app',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/auth-mailbox/, ''),
      },
    },
  },
  test: {
    environment: 'jsdom',
    // `tsc -b` writes declarations under dist-types/. Without this, vitest
    // discovers the compiled copies of the test files and runs them a second
    // time, from a directory where their relative paths no longer resolve.
    exclude: ['**/node_modules/**', '**/dist/**', '**/dist-types/**'],
  },
});
