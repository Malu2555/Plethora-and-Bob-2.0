/**
 * Vite configuration for the Sentinel Monitor frontend.
 *
 * Developer experience:
 *   * the dev server binds :5173 with strictPort (matching the backend's
 *     CORS_ALLOWED_ORIGINS for direct browser calls)
 *   * `/api` requests are proxied to the Django backend on :8000, so under
 *     `npm run dev` the browser only ever talks to one origin (no CORS hit)
 *   * Tailwind CSS v4 is wired through @tailwindcss/vite (no PostCSS config)
 */
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
