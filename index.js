const express = require('express')
const app = express()
app.use(express.text({ type: '*/*' }))

app.get('/ip', async (req, res) => {
  const r = await fetch('https://api4.ipify.org?format=json')
  const data = await r.json()
  res.json(data)
})

app.post('/', async (req, res) => {
  const secret = req.headers['x-worker-secret']
  if (process.env.WORKER_SECRET && secret !== process.env.WORKER_SECRET) {
    return res.status(401).send('Unauthorized')
  }
  const targetUrl = req.headers['x-target-url']
  if (!targetUrl) return res.status(400).send('X-Target-Url header required')

  const r = await fetch(targetUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: req.body,
  })
  const text = await r.text()
  res.status(r.status).set('Content-Type', 'application/json').send(text)
})

app.listen(process.env.PORT || 3000, () => console.log('ready'))
