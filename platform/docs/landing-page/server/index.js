/**
 * Optional "light" backend for the landing project.
 * Google Forms embedded in the React app do NOT call this server.
 *
 * Use this later if you add a custom HTML form or Zapier/Make webhook
 * that POSTs JSON to your own infrastructure.
 */
import http from 'node:http'

const PORT = Number(process.env.PORT || 3847)

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, service: 'connector-landing-notify' }))
    return
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' })
  res.end('Not found. GET /health')
})

server.listen(PORT, () => {
  console.log(`landing notify stub http://127.0.0.1:${PORT}/health`)
})
