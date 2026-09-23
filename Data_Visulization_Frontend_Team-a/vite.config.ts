import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');

  // Local backend by default; Render backend can be supplied through VITE_API_URL.
  const apiTarget =
    env.VITE_API_URL || 'https://infosys-2g89.onrender.com';

  return {
    plugins: [react(), tailwindcss()],

    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },

    server: {
      port: 3000,
      host: '0.0.0.0',

      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
          secure: true,
        },

        '/events': {
          target: apiTarget,
          changeOrigin: true,
          secure: true,
        },

        '/stats': {
          target: apiTarget,
          changeOrigin: true,
          secure: true,
        },

        '/threats': {
          target: apiTarget,
          changeOrigin: true,
          secure: true,
        },
      },

      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
