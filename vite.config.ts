import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { crx } from '@crxjs/vite-plugin'
import manifest from './manifest.json'
import path from 'path'
import hotReloadExtension from 'hot-reload-extension-vite';


export default defineConfig({
  plugins: [
    hotReloadExtension({
      log: true,
      backgroundPath: 'src/background.ts' // src/pages/background/index.ts
    }),
    react(),
    crx({ manifest }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },

  build: {
    rollupOptions: {
      output: {
        
        entryFileNames: 'assets/[name].js',  // No hash in filename
        chunkFileNames: 'assets/[name].js',  // No hash in chunk filenames
        assetFileNames: 'assets/[name][extname]',  // No hash in asset filenames (like images or CSS)
      },
    },
    // Optional: Disable minification if needed (though generally not recommended for production)
    minify: false,
  },
  publicDir: "public",
})
