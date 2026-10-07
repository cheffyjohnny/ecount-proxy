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

// 업타임 모니터링용 (외부 호출 없음)
app.get('/health', (req, res) => res.send('ok'))

// Express 4는 async 핸들러 에러를 잡지 않으므로 try/catch 없이 throw되면 프로세스가 종료됨
app.get('/ip', async (req, res) => {
  try {
    const r = await fetch('https://api4.ipify.org?format=json', { signal: AbortSignal.timeout(5000) })
    res.json(await r.json())
  } catch (e) {
    res.status(502).json({ error: 'ip lookup failed', detail: String(e?.cause?.code || e.message) })
  }
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

  try {
    const r = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: req.body,
      signal: AbortSignal.timeout(30000),
    })
    const text = await r.text()
    res.status(r.status).set('Content-Type', 'application/json').send(text)
  } catch (e) {
    res.status(502).send(`proxy fetch failed: ${e?.cause?.code || e.message}`)
  }
})

app.listen(process.env.PORT || 3000, () => console.log('ready'))
