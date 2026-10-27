import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import fs from 'fs'
import path from 'path'
import { defineConfig } from 'vite'

const apiPlugin = () => ({
  name: 'api-plugin',
  configureServer(server) {
    server.middlewares.use('/api', (req, res, next) => {
      const url = req.url?.split('?')[0] || '/'
      const filePath = path.join(import.meta.dirname, '..', 'output', url)
      
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        res.setHeader('Content-Type', 'application/json')
        res.end(fs.readFileSync(filePath, 'utf-8'))
      } else {
        next()
      }
    })
  }
})

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), apiPlugin()],
})
