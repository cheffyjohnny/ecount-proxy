const express = require('express')
const crypto = require('crypto')
const rateLimit = require('express-rate-limit')
const app = express()
app.use(express.text({ type: '*/*' }))

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
})

// 길이가 달라도 안전하게, 타이밍 공격을 피하기 위해 해시로 비교
function safeEqual(a, b) {
  const ah = crypto.createHash('sha256').update(String(a)).digest()
  const bh = crypto.createHash('sha256').update(String(b)).digest()
  return crypto.timingSafeEqual(ah, bh)
}

app.get('/ip', async (req, res) => {
  const r = await fetch('https://api4.ipify.org?format=json')
  const data = await r.json()
  res.json(data)
})

app.post('/', authLimiter, async (req, res) => {
  if (!process.env.WORKER_SECRET) {
    return res.status(500).send('WORKER_SECRET not configured')
  }
  const secret = req.headers['x-worker-secret']
  if (!secret || !safeEqual(secret, process.env.WORKER_SECRET)) {
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
