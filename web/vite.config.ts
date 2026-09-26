import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8000' } },
  build: {
    // The libraries change on an upgrade, the application changes on every
    // release: splitting them lets a deployment reuse the cached vendor chunk
    // instead of making every visitor download 650 kB again.
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler|react-router|react-router-dom)[\\/]/.test(id)) return 'react'
          if (id.includes('@tanstack')) return 'query'
          if (/i18next/.test(id)) return 'i18n'
          if (id.includes('lucide-react')) return 'icons'
          return 'vendor'
        },
      },
    },
  },
})
