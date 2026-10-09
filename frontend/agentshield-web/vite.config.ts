import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  // Dev-only: the browser talks to the Vite origin and Vite forwards to the API, so no CORS is needed locally.
  const apiTarget = env.VITE_API_PROXY_TARGET ?? 'http://localhost:5102'
  // Dev-only: the proxy (Node, not the browser) authenticates /api calls with the API's public Development key, which
  // the API accepts only in its Development environment. Deliberately not a VITE_* variable: it never enters the bundle.
  const devApiKey = env.AGENTSHIELD_DEV_API_KEY || 'agentshield-development-only-key-not-a-secret'

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    // No CORS on the dev and preview servers (H-08): the proxy adds the Development key, so only pages from the Vite origin
    // itself may call it. Vite's default would also let any other localhost origin read the proxied responses.
    server: {
      cors: false,
      proxy: {
        '/api': { target: apiTarget, changeOrigin: true, headers: { 'X-API-Key': devApiKey } },
        '/health': { target: apiTarget, changeOrigin: true },
      },
    },
    // `preview.proxy` inherits `server.proxy`; CORS is stated explicitly here too.
    preview: {
      cors: false,
    },
  }
})
