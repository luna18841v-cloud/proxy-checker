// সব ব্যাকএন্ড এক ফাইলে — কোনো আলাদা import নেই।
import { connect } from 'cloudflare:sockets'

const FRAUD_MAX = 20
const SEEN_OK = new Set(['', '-', '0'])
const ECHO_MIN = 4000
const CAP = 900_000
const BATCH_MAX = 25
const BATCH_WAIT = 1200

const UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
]
const pickUa = () => UAS[Math.floor(Math.random() * UAS.length)]
const HTML_HDR = () => ({ 'User-Agent': pickUa(),
  'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9' })
const JSON_HDR = { 'User-Agent': UAS[0], 'Accept': 'application/json,*/*;q=0.8' }
const MM_HDR = () => ({ ...HTML_HDR(), 'Referer': 'https://www.maxmind.com/en/geoip-web-services-demo' })

const SL_PAGE = ip => 'https://scamalytics.com/ip/' + encodeURIComponent(ip)
const I2L_PAGE = ip => 'https://www.ip2location.com/demo/' + encodeURIComponent(ip)
const MM_BULK = ips => 'https://www.maxmind.com/en/geoip-web-services-demo?ip_address=' +
  ips.map(encodeURIComponent).join(',')
const MM_ONE = ip => 'https://www.maxmind.com/en/geoip-web-services-demo/' + encodeURIComponent(ip)
const ALLOW = /^https:\/\/(?:www\.)?(?:maxmind\.com|scamalytics\.com|ip2location\.com)\//
const IPAPI_IS = (ip, key) => `https://api.ipapi.is/?q=${encodeURIComponent(ip)}&key=${encodeURIComponent(key)}`

const ECHO_HTTP = ['http://api.ipify.org/?format=json', 'http://checkip.amazonaws.com/',
  'http://icanhazip.com/', 'http://ip-api.com/json/?fields=query', 'http://ifconfig.me/ip']
const ECHO_HTTPS = ['https://api.ipify.org?format=json', 'https://api64.ipify.org?format=json',
  'https://api.ipapi.is/', 'https://ipapi.co/ip/', 'https://ifconfig.me/all.json',
  'https://icanhazip.com/', 'https://checkip.amazonaws.com/']

const relays = u => ['https://r.jina.ai/' + u,
  'https://api.codetabs.com/v1/proxy/?quest=' + encodeURIComponent(u),
  'https://api.allorigins.win/raw?url=' + encodeURIComponent(u)]

// ক্যাশ
const SL_TTL = 30 * 60 * 1000
const CT_TTL = 7 * 24 * 3600 * 1000
const CTX_TTL = 3 * 60 * 1000
const RES_TTL = 15 * 60 * 1000
const MEM = new Map()
function memGet(k, ttl) { const h = MEM.get(k); return h && Date.now() - h.t < ttl ? h.v : undefined }
function memSet(k, v) { if (MEM.size > 8000) MEM.clear(); MEM.set(k, { t: Date.now(), v }) }
const inflight = new Map()

const CT_RE = /"connection_type"\s*:\s*"([^"]+)"/i
const CT_ANY = /(Cable\/DSL|Cellular|Corporate|Satellite)/i

const FIELDS = ['proxy', 'scheme', 'ip', 'verdict', 'reasons', 'src', 'sl_src', 'i2l_src', 'ct_src',
                'sl_vpn', 'sl_rproxy', 'sl_dc', 'i2l_anon', 'i2l_fraud', 'i2l_seen', 'api_flags',
                'mm_ct', 'mm_asn', 'mm_asnorg', 'mm_isp', 'mm_org', 'mm_lat', 'mm_lon', 'mm_net', 'secs']
const blank = p => Object.fromEntries([...FIELDS.map(f => [f, '']), ['proxy', p]])
const rnd = (a, b) => a + Math.random() * (b - a)
const sleep = ms => new Promise(r => setTimeout(r, ms))
const TE = new TextEncoder()
const normWorker = w => String(w || '').trim().replace(/\/+$/, '')

// ---------- সকেট র‍্যাপার ----------
class RawSock {
  constructor(cf) {
    this._s = cf
    this._h = { data: [], error: [], close: [] }
    this._dead = false
    this._wq = null
    this.opened = cf.opened
    this._reader = cf.readable.getReader()
    this._writer = cf.writable.getWriter()
    this._pump()
  }
  on(ev, fn) { (this._h[ev] || (this._h[ev] = [])).push(fn); return this }
  _off(ev, fn) { const a = this._h[ev]; if (a) { const i = a.indexOf(fn); if (i !== -1) a.splice(i, 1) } }
  removeAllListeners(ev) { if (ev) this._h[ev] = []; else this._h = { data: [], error: [], close: [] } }
  _emit(ev, a) { for (const f of (this._h[ev] || []).slice()) { try { f(a) } catch {} } }
  async _pump() {
    try {
      for (;;) {
        const r = await this._reader.read()
        if (r.done) break
        if (r.value) this._emit('data', Buffer.from(r.value))
      }
    } catch (e) { if (!this._dead) this._emit('error', e) }
    this._emit('close')
  }
  write(d) {
    const u8 = typeof d === 'string' ? TE.encode(d) : (d instanceof Uint8Array ? d : new Uint8Array(d))
    this._wq = (this._wq || Promise.resolve()).then(() => this._writer.write(u8)).catch(e => this._emit('error', e))
    return true
  }
  destroy() {
    if (this._dead) return
    this._dead = true
    try { this._reader.cancel() } catch {}
    try { this._s.close() } catch {}
    try { this._writer.releaseLock() } catch {}
    this._emit('close')
  }
  async startTls(host) {
    try { if (this._wq) await this._wq } catch {}
    this._dead = true
    this._h = { data: [], error: [], close: [] }
    try { this._reader.releaseLock() } catch {}
    try { this._writer.releaseLock() } catch {}
    const open = o => { try { return this._s.startTls(o) } catch { return null } }
    const cf = open({ expectedServerHostname: host }) || open({ servername: host }) || this._s.startTls()
    const s = new RawSock(cf)
    await s.opened
    return s
  }
}

async function openTcp(host, port, timeout) {
  const cf = connect({ hostname: host, port: Number(port) }, { secureTransport: 'starttls' })
  const s = new RawSock(cf)
  s.on('error', () => {})
  let timer
  const guard = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('tcp timeout')), timeout) })
  try { await Promise.race([s.opened, guard]) }
  catch (e) { s.destroy(); throw e }
  finally { clearTimeout(timer) }
  return s
}

// ---------- পার্স ----------
function parseProxy(line) {
  const raw = String(line || '').trim()
  if (!raw || raw.startsWith('#')) return null
  let body = raw, scheme = ''
  const m = body.match(/^(https?|socks5h?|socks4a?):\/\//i)
  if (m) { scheme = m[1].toLowerCase(); body = body.slice(m[0].length) }
  if (scheme === 'socks5h') scheme = 'socks5'
  else if (scheme === 'socks4a') scheme = 'socks4'
  else if (scheme === 'https') scheme = 'http'
  let user = null, pw = null
  if (body.includes('@')) {
    const i = body.lastIndexOf('@'), cred = body.slice(0, i)
    body = body.slice(i + 1)
    const c = cred.split(':')
    user = c[0]; pw = c.length > 1 ? c[1] : null
  }
  const parts = body.split(':')
  if (parts.length < 2 || !/^\d+$/.test(parts[1])) return null
  const host = parts[0], port = Number(parts[1])
  if (parts.length === 4) { user = parts[2]; pw = parts[3] }
  else if (parts.length === 3 && user === null) user = parts[2]
  return { raw, scheme, host, port, user, pw }
}

const validIp = v => {
  v = String(v || '').trim().replace(/^"|"$/g, '')
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v)) return v
  if (/^[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}$/i.test(v)) return v
  return ''
}

// ---------- টানেল ----------
function tunnel(p, host, port, timeout) {
  if (p.scheme === 'socks5') return socks5(p, host, port, timeout)
  if (p.scheme === 'socks4') return socks4(p, host, port, timeout)
  return httpConnect(p, host, port, timeout)
}

async function httpConnect(p, host, port, timeout) {
  const s = await openTcp(p.host, p.port, timeout)
  const auth = p.user ? 'Basic ' + Buffer.from(p.user + ':' + (p.pw || '')).toString('base64') : ''
  return new Promise((res, rej) => {
    let buf = '', ok = false
    const fail = e => { if (ok) return; ok = true; s.removeAllListeners('data'); s.destroy(); rej(e) }
    const t = setTimeout(() => fail(new Error('connect timeout')), timeout)
    s.on('error', fail)
    s.on('data', d => {
      if (ok) return
      buf += d.toString('latin1')
      const i = buf.indexOf('\r\n\r\n')
      if (i === -1) { if (buf.length > 16384) fail(new Error('connect hdr too big')); return }
      const code = Number((buf.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/) || [])[1] || 0)
      clearTimeout(t); s.removeAllListeners('data'); s.removeAllListeners('error')
      if (code !== 200) return fail(new Error('proxy ' + (code || '?')))
      ok = true; res(s)
    })
    s.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n` +
      (auth ? `Proxy-Authorization: ${auth}\r\n` : '') + 'Proxy-Connection: keep-alive\r\n\r\n')
  })
}

async function socks5(p, host, port, timeout) {
  const s = await openTcp(p.host, p.port, timeout)
  return new Promise((res, rej) => {
    let stage = 0, ok = false
    const fail = e => { if (ok) return; ok = true; s.removeAllListeners('data'); s.destroy(); rej(e) }
    const t = setTimeout(() => fail(new Error('socks timeout')), timeout)
    s.on('error', fail)
    const send = () => {
      stage = 3
      const hb = TE.encode(host)
      const out = new Uint8Array(7 + hb.length)
      out[0] = 5; out[1] = 1; out[2] = 0; out[3] = 3; out[4] = hb.length
      out.set(hb, 5)
      out[5 + hb.length] = (port >> 8) & 255
      out[6 + hb.length] = port & 255
      s.write(out)
    }
    s.on('data', d => {
      if (ok) return
      if (stage === 0) {
        if (d[0] !== 5) return fail(new Error('socks5 bad'))
        if (d[1] === 2) {
          const u = TE.encode(p.user || ''), w = TE.encode(p.pw || '')
          const out = new Uint8Array(3 + u.length + w.length)
          out[0] = 1; out[1] = u.length
          out.set(u, 2)
          out[2 + u.length] = w.length
          out.set(w, 3 + u.length)
          s.write(out); stage = 1; return
        }
        if (d[1] !== 0) return fail(new Error('socks5 auth needed'))
        return send()
      }
      if (stage === 1) { if (d[1] !== 0) return fail(new Error('socks5 auth fail')); return send() }
      if (stage === 3 && d.length >= 2) {
        if (d[1] !== 0) return fail(new Error('socks5 rep ' + d[1]))
        clearTimeout(t); s.removeAllListeners('data'); s.removeAllListeners('error')
        ok = true; res(s)
      }
    })
    s.write(p.user ? Uint8Array.from([5, 2, 0, 2]) : Uint8Array.from([5, 1, 0]))
  })
}

async function socks4(p, host, port, timeout) {
  const s = await openTcp(p.host, p.port, timeout)
  return new Promise((res, rej) => {
    let ok = false
    const fail = e => { if (ok) return; ok = true; s.removeAllListeners('data'); s.destroy(); rej(e) }
    const t = setTimeout(() => fail(new Error('socks timeout')), timeout)
    s.on('error', fail)
    s.on('data', d => {
      if (ok) return
      if (d[0] !== 0 || d[1] !== 0x5a) return fail(new Error('socks4 reject'))
      clearTimeout(t); s.removeAllListeners('data'); s.removeAllListeners('error')
      ok = true; res(s)
    })
    const hb = TE.encode(host), ub = TE.encode((p.user || '') + '\0')
    const out = new Uint8Array(9 + ub.length + hb.length)
    out[0] = 4; out[1] = 1; out[2] = (port >> 8) & 255; out[3] = port & 255
    out[4] = 0; out[5] = 0; out[6] = 0; out[7] = 1
    out.set(ub, 8)
    out.set(hb, 8 + ub.length)
    s.write(out)
  })
}

const tlsWrap = (sock, host) => sock.startTls(host)

// ---------- কাঁচা HTTP ----------
function dechunk(b) {
  const out = []; let i = 0
  for (;;) {
    const j = b.indexOf('\r\n', i)
    if (j === -1) return null
    const size = parseInt(b.slice(i, j).toString('latin1').trim(), 16)
    if (!Number.isFinite(size)) return null
    if (size === 0) return Buffer.concat(out)
    if (b.length < j + 2 + size + 2) return null
    out.push(b.slice(j + 2, j + 2 + size))
    i = j + 2 + size + 2
  }
}

function rawRequest(sock, { host, path, headers, timeout = 6000 }) {
  return new Promise(resolve => {
    let buf = Buffer.alloc(0), done = false, parsed = false, mode = '', need = 0, status = 0
    let hdrs = {}
    const finish = v => { if (done) return; done = true; clearTimeout(timer); try { sock.destroy() } catch {} ; resolve(v) }
    const timer = setTimeout(() => finish(null), timeout)
    sock.on('data', d => {
      if (done) return
      buf = Buffer.concat([buf, d])
      if (buf.length > CAP) return finish(null)
      if (!parsed) {
        const i = buf.indexOf('\r\n\r\n')
        if (i === -1) return
        const lines = buf.slice(0, i).toString('latin1').split('\r\n')
        const m = lines[0].match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/)
        if (!m) return finish(null)
        status = Number(m[1])
        for (const l of lines.slice(1)) {
          const k = l.indexOf(':')
          if (k > 0) hdrs[l.slice(0, k).trim().toLowerCase()] = l.slice(k + 1).trim()
        }
        buf = buf.slice(i + 4)
        parsed = true
        if (/chunked/i.test(hdrs['transfer-encoding'] || '')) mode = 'chunk'
        else if (hdrs['content-length'] != null) { mode = 'len'; need = Number(hdrs['content-length']) || 0 }
        else mode = 'close'
      }
      if (mode === 'len' && buf.length >= need) return finish({ status, headers: hdrs, body: buf.slice(0, need) })
      if (mode === 'chunk') { const r = dechunk(buf); if (r) finish({ status, headers: hdrs, body: r }) }
    })
    sock.on('error', () => finish(null))
    sock.on('close', () => { if (!done) finish({ status, headers: hdrs, body: buf }) })
    sock.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\n` +
      Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
      '\r\nConnection: close\r\n\r\n')
  })
}

async function plainRequest(u, headers, timeout) {
  const h = { ...headers }
  delete h['Accept-Encoding']
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeout)
  try {
    const r = await fetch(u.toString(), { headers: h, signal: ctl.signal, redirect: 'manual' })
    const cl = Number(r.headers.get('content-length') || 0)
    if (cl > CAP) return null
    const ab = await r.arrayBuffer()
    if (ab.byteLength > CAP) return null
    return { status: r.status, headers: Object.fromEntries(r.headers), body: Buffer.from(ab) }
  } catch { return null } finally { clearTimeout(timer) }
}

async function requestText(url, opts = {}) {
  const { proxy, timeout = 6000, headers = HTML_HDR(), minLen = 0, needIp = '', redirects = 4 } = opts
  const u = new URL(url)
  const hdrs = { ...headers, 'Accept-Encoding': 'identity' }
  let r = null
  if (proxy) {
    let sock
    try { sock = await tunnel(proxy, u.hostname, Number(u.port) || (u.protocol === 'https:' ? 443 : 80), timeout) } catch { return null }
    if (u.protocol === 'https:') {
      try { sock = await tlsWrap(sock, u.hostname) } catch { try { sock.destroy() } catch {} ; return null }
    }
    r = await rawRequest(sock, { host: u.host, path: u.pathname + u.search, headers: hdrs, timeout })
  } else {
    r = await plainRequest(u, hdrs, timeout)
  }
  if (!r) return null
  if (r.status >= 300 && r.status < 400 && r.headers.location && redirects > 0) {
    return requestText(new URL(r.headers.location, u).toString(), { ...opts, redirects: redirects - 1 })
  }
  const text = Buffer.isBuffer(r.body) ? r.body.toString('utf8') : String(r.body || '')
  if (r.status !== 200 || text.length < minLen) return null
  if (needIp && !text.includes(needIp)) return null
  return text
}

// ---------- HTML → মান ----------
const TAG = /<[^>]+>/g
const stripTags = s => String(s || '').replace(TAG, ' ')
  .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#39;/g, "'")
  .replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')

// লেবেল → ঠিক পরের <td> সেল (কমেন্ট/সাবটাইটেল এড়াতে ট্যাগ-ফর্ম ধরে)
function cellOf(html, label, wrap) {
  const open = wrap === 'th' ? '<th>' + label + '</th>' : '<strong>' + label + '</strong>'
  let i = html.indexOf(open)
  if (i === -1) return null
  const from = i + open.length
  const td = html.indexOf('<td', from)
  if (td === -1 || td - from > 600) return null
  const close = html.indexOf('</td>', td)
  if (close === -1) return null
  return stripTags(html.slice(td, close)).replace(/\s+/g, ' ').trim()
}

// ফলব্যাক: সব occurrence লুপ, উইন্ডো চওড়া
function nearVal(html, label, re) {
  const lc = html.indexOf(label)
  if (lc === -1) return ''
  let i = lc
  while (i !== -1) {
    const seg = stripTags(html.slice(i + label.length, i + label.length + 400)).replace(/\s+/g, ' ')
    const m = seg.match(re)
    if (m) return m[1].toUpperCase()
    i = html.indexOf(label, i + label.length)
  }
  return ''
}

const YN = /\b(Yes|No|N\/A|True|False)\b/i
const pick = (cell, re, fb) => {
  const c = cell || ''
  const m = c.match(re)
  return m ? m[1].toUpperCase() : fb
}

function parseSl(t) {
  if (!t) return null
  const o = {
    vpn: pick(cellOf(t, 'Anonymizing VPN', 'th'), YN, nearVal(t, 'Anonymizing VPN', YN)),
    rproxy: pick(cellOf(t, 'Residential Proxy', 'th'), YN, nearVal(t, 'Residential Proxy', YN)),
    dc: pick(cellOf(t, 'Datacenter', 'th'), YN, nearVal(t, 'Datacenter', YN))
  }
  return (o.vpn || o.dc || o.rproxy) ? o : null
}

function seenOf(t) {
  const c = cellOf(t, 'Last Seen', 'strong') || ''
  const s = c.replace(/^[\s|:*#-]+/, '').trim()
  const m = s.match(new RegExp(String.raw`^(?:-|\d+\s*(?:second|minute|hour|day|week|month|year)s?\s*ago|\d{4}-\d{2}-\d{2})`, 'i'))
  if (m) return m[0]
  const i = t.indexOf('Last Seen')
  if (i === -1) return ''
  const seg = stripTags(t.slice(i + 9, i + 300)).replace(/\s+/g, ' ').replace(/^[\s|:*#-]+/, '').trim()
  const m2 = seg.match(new RegExp(String.raw`^(?:-|\d+\s*(?:second|minute|hour|day|week|month|year)s?\s*ago|\d{4}-\d{2}-\d{2})`, 'i'))
  return m2 ? m2[0] : ''
}

function parseI2l(t) {
  if (!t) return null
  const anon = pick(cellOf(t, 'Anonymous Proxy', 'strong'), YN, nearVal(t, 'Anonymous Proxy', YN))
  const fraud = pick(cellOf(t, 'Fraud Score', 'strong'), /(\d{1,3})/, nearVal(t, 'Fraud Score', /(\d{1,3})/))
  const seen = seenOf(t)
  if (!(anon || fraud || seen)) {
    const f = t.match(/"fraud_score"\s*:\s*(\d{1,3})/i)
    const p = t.match(/"is_proxy"\s*:\s*(true|false)/i)
    if (!f && !p) return null
    return { anon: p ? (p[1].toLowerCase() === 'true' ? 'YES' : 'NO') : '', seen: '', fraud: f ? f[1] : '' }
  }
  return { anon, seen, fraud }
}

const yn = v => ({ YES: 'YES', TRUE: 'YES', NO: 'NO', FALSE: 'NO', 'N/A': 'N/A' }[String(v || '').trim().toUpperCase()] || '')

function parseWSl(j) {
  if (!j) return null
  const o = { vpn: yn(j.vpn), rproxy: yn(j.rproxy), dc: yn(j.dc) }
  return (o.vpn || o.dc || o.rproxy) ? o : null
}

function parseWI2l(j) {
  if (!j) return null
  const o = { anon: yn(j.anon), seen: String(j.seen || '').trim().slice(0, 40),
              fraud: String(j.fraud || '').replace(/\D/g, '').slice(0, 3) }
  return (o.anon || o.fraud || o.seen) ? o : null
}

function seenDays(v) {
  const m = String(v || '').match(new RegExp(String.raw`(\d+)\s*(second|minute|hour|day|week|month|year)s?\s*ago`, 'i'))
  if (!m) return null
  const mult = { second: 1 / 86400, minute: 1 / 1440, hour: 1 / 24, day: 1, week: 7, month: 30, year: 365 }[m[2].toLowerCase()]
  return Number(m[1]) * mult
}

const fraudNum = v => /^\d+$/.test(String(v || '').trim()) ? Number(v) : null

function slVerdict(p) {
  if (!p || !(p.vpn || p.dc)) return ['UNKNOWN', 'no data']
  const bad = ['vpn', 'dc'].filter(k => p[k] === 'YES')
  if (bad.length) return ['FAIL', 'flagged: ' + bad.join(',')]
  if (p.vpn !== 'NO' || p.dc !== 'NO') return ['UNKNOWN', 'vpn/dc unreadable']
  return ['PASS', `vpn=No dc=No rproxy=${p.rproxy || '-'}`]
}

function i2lVerdict(p) {
  if (!p || !(p.anon || p.fraud || p.seen)) return ['UNKNOWN', 'no data']
  if (p.anon !== 'NO') return p.anon === 'YES' ? ['FAIL', 'anonymous proxy'] : ['UNKNOWN', 'anon unreadable']
  const fv = fraudNum(p.fraud)
  if (fv === null) return ['UNKNOWN', 'fraud unreadable']
  if (fv >= FRAUD_MAX) return ['FAIL', `fraud ${fv} >= ${FRAUD_MAX}`]
  const seen = String(p.seen || '').trim()
  if (!SEEN_OK.has(seen) && seenDays(seen) !== 0) return ['FAIL', `last seen '${seen}'`]
  return ['PASS', `anon=No fraud=${fv} seen='${seen || '-'}'`]
}

// ---------- MaxMind (একমাত্র CT সোর্স, ২৫ IP ব্যাচ) ----------
function normCt(v) {
  const s = String(v || '').trim().toLowerCase()
  if (s.includes('cable') || s.includes('dsl')) return 'Cable/DSL'
  if (s.includes('cell')) return 'Cellular'
  if (s.includes('corp')) return 'Corporate'
  if (s.includes('sat')) return 'Satellite'
  if (s.includes('data') || s.includes('host')) return 'Data Center'
  return ''
}

const js = (s, k) => { const m = String(s || '').match(new RegExp('"' + k + '"\\s*:\\s*"([^"]*)"', 'i')); return m ? m[1] : '' }
const jn = (s, k) => { const m = String(s || '').match(new RegExp('"' + k + '"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)', 'i')); return m ? m[1] : '' }

// একই রো-এর সেল (HTML <tr> বা markdown | |)
function rowCells(t, ip) {
  let i = t.indexOf('geoip-web-services-demo/' + ip)
  if (i === -1) i = t.indexOf('>' + ip + '<')
  if (i === -1) return null
  const hs = t.lastIndexOf('<tr', i), he = t.indexOf('</tr>', i)
  if (hs !== -1 && he !== -1 && he > hs) {
    return t.slice(hs, he).split(/<td[^>]*>/i).slice(1)
      .map(c => stripTags(c).replace(/\s+/g, ' ').trim())
  }
  const ms = t.lastIndexOf('\n', i), me = t.indexOf('\n', i)
  if (ms === -1 || me === -1) return null
  const cells = t.slice(ms, me).split('|')
    .map(c => c.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/\s+/g, ' ').trim())
  if (cells.length && cells[0] === '') cells.shift()
  if (cells.length && cells[cells.length - 1] === '') cells.pop()
  return cells
}

function parseMm(t, ip) {
  if (!t || !t.includes(ip)) return null
  const o = { ct: '', asn: '', asnorg: '', isp: '', org: '', lat: '', lon: '', net: '' }

  const ci = t.indexOf('"connection_type"')
  if (ci !== -1) { const m = t.slice(ci, ci + 80).match(CT_RE); if (m) o.ct = normCt(m[1]) }

  const ti = t.indexOf('"traits"')
  if (ti !== -1) {
    const seg = t.slice(ti, ti + 1600)
    const a = jn(seg, 'autonomous_system_number')
    o.asn = a ? 'AS' + a : ''
    o.asnorg = js(seg, 'autonomous_system_organization')
    o.isp = js(seg, 'isp'); o.org = js(seg, 'organization'); o.net = js(seg, 'network')
    const li = t.indexOf('"location"')
    if (li !== -1) { const ls = t.slice(li, li + 400); o.lat = jn(ls, 'latitude'); o.lon = jn(ls, 'longitude') }
  }

  if (!o.ct || !o.isp) {
    const row = rowCells(t, ip)
    if (row && row.length >= 6) {
      const ct = normCt(row[row.length - 1])
      if (!o.ct && ct) o.ct = ct
      if (!o.isp) {
        const isp = row[row.length - 3]
        if (isp && isp !== '-') { o.isp = isp; o.org = o.org || isp }
      }
      if (!o.net) { const n = row[2]; if (n && n !== '-' && n.includes('/')) o.net = n }
      if (!o.lat) {
        const g = String(row[4] || '').match(/(-?\d+\.\d+),\s*(-?\d+\.\d+)/)
        if (g) { o.lat = g[1]; o.lon = g[2] }
      }
    }
  }

  if (!o.ct) {
    const k = t.indexOf('Connection type')
    if (k !== -1) { const m = stripTags(t.slice(k, k + 160)).match(CT_ANY); if (m) o.ct = normCt(m[1]) }
  }

  return (o.ct || o.asn || o.isp) ? o : null
}

// স্থায়ী ক্যাশ
async function cdnRead(ip) {
  try {
    const r = await caches.default.match('https://mm-cache.internal/' + ip)
    return r ? await r.json() : null
  } catch { return null }
}
function cdnWrite(ip, v) {
  try {
    caches.default.put('https://mm-cache.internal/' + ip,
      new Response(JSON.stringify(v), { headers: { 'Cache-Control': 'max-age=604800' } }))
  } catch {}
}

// ব্যাচ কিউ
let BATCH = []
let BTIMER = null

function mmEnqueue(ip) {
  return new Promise(res => {
    BATCH.push({ ip, res })
    if (BATCH.length >= BATCH_MAX) flushBatch()
    else if (!BTIMER) BTIMER = setTimeout(flushBatch, BATCH_WAIT)
  })
}

async function flushBatch() {
  if (BTIMER) { clearTimeout(BTIMER); BTIMER = null }
  const jobs = BATCH
  BATCH = []
  if (!jobs.length) return
  const ips = jobs.map(j => j.ip)
  const url = MM_BULK(ips)
  let text = await page(url, ips[0])
  if (!text) text = await viaRelay(url, ips[0])
  if (!text) {
    for (const j of jobs) { memSet('mmx:' + j.ip, 1); j.res(null) }
    return
  }
  for (const j of jobs) {
    const v = parseMm(text, j.ip)
    if (v && v.ct) { memSet('mm:' + j.ip, v); cdnWrite(j.ip, v) } else memSet('mmx:' + j.ip, 1)
    j.res(v || null)
  }
}

async function mmInfo(ip) {
  const hit = memGet('mm:' + ip, CT_TTL)
  if (hit) return hit
  if (memGet('mmx:' + ip, CTX_TTL)) return null
  if (inflight.has(ip)) return inflight.get(ip)

  const pr = (async () => {
    const c = await cdnRead(ip)
    if (c && c.ct) { memSet('mm:' + ip, c); return c }
    const v = await mmEnqueue(ip)
    if (!v) {
      const one = await page(MM_ONE(ip), ip)
      const s = one ? parseMm(one, ip) : null
      if (s && s.ct) { memSet('mm:' + ip, s); cdnWrite(ip, s); return s }
    }
    return v
  })()

  inflight.set(ip, pr)
  try { return await pr } finally { inflight.delete(ip) }
}

// ---------- ঐচ্ছিক: ipapi.is (শুধু ভের্ডিক্ট ফ্ল্যাগ) ----------
async function ipapiIs(ip, key) {
  const c = memGet('api:' + ip, CT_TTL)
  if (c !== undefined) return c
  const t = await requestText(IPAPI_IS(ip, key), { timeout: 4500, headers: JSON_HDR })
  let v = null
  if (t) {
    try {
      const j = JSON.parse(t)
      if (j && !j.error && !j.docs) {
        v = { is_mobile: !!j.is_mobile, is_datacenter: !!j.is_datacenter,
              is_proxy: !!j.is_proxy, is_vpn: !!j.is_vpn,
              is_tor: !!j.is_tor, is_abuser: !!j.is_abuser }
      }
    } catch {}
  }
  if (v) memSet('api:' + ip, v)
  return v
}

function apiVerdict(a) {
  if (!a) return null
  const bad = []
  if (a.is_tor) bad.push('tor')
  if (a.is_vpn) bad.push('vpn')
  if (a.is_proxy) bad.push('proxy')
  if (a.is_datacenter) bad.push('dc')
  if (a.is_abuser) bad.push('abuser')
  if (bad.length) return ['FAIL', 'ipapi.is: ' + bad.join(',')]
  return ['PASS', 'ipapi.is: clean']
}

// ---------- ধাপ ----------
async function tryEcho(p, urls, timeout) {
  for (const url of urls) {
    const t = await requestText(url, { proxy: p, timeout, headers: JSON_HDR })
    if (!t) continue
    let ip = ''
    try {
      const j = JSON.parse(t)
      ip = validIp(j.ip || j.ipAddress || j.ip_addr || j.query || '')
    } catch {}
    if (!ip) { const m = t.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/); ip = validIp(m ? m[0] : '') }
    if (!ip) { const m = t.match(/[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}/i); ip = validIp(m ? m[0] : '') }
    if (ip) return ip
  }
  return ''
}

function firstOk(tasks) {
  return new Promise(res => {
    let n = tasks.length, done = false
    const settle = v => { n--; if (v && !done) { done = true; res(v) } else if (n === 0 && !done) { done = true; res(null) } }
    for (const t of tasks) t.then(settle, () => settle(null))
  })
}

async function exitIp(p, budget) {
  const per = Math.min(12000, Math.max(ECHO_MIN, Math.round(budget * 500)))
  const socksFirst = p.scheme === 'socks5' || p.scheme === 'socks4'
  const A = socksFirst ? 'socks5' : 'http'
  const B = socksFirst ? 'http' : 'socks5'

  const plain = [...ECHO_HTTP].sort(() => Math.random() - 0.5)
  const p1 = await firstOk([
    tryEcho({ ...p, scheme: A }, plain.slice(0, 2), per).then(ip => ip && { ip, scheme: A }),
    tryEcho({ ...p, scheme: B }, plain.slice(2, 3), per).then(ip => ip && { ip, scheme: B })
  ])
  if (p1) return p1

  const tlsUrls = [...ECHO_HTTPS].sort(() => Math.random() - 0.5)
  const got = await firstOk([
    tryEcho({ ...p, scheme: A }, tlsUrls.slice(0, 1), per).then(ip => ip && { ip, scheme: A }),
    tryEcho({ ...p, scheme: B }, tlsUrls.slice(1, 2), per).then(ip => ip && { ip, scheme: B })
  ])
  if (got) return got
  const rest = await tryEcho({ ...p, scheme: A }, tlsUrls.slice(2, 4), per)
  return rest ? { ip: rest, scheme: A } : null
}

async function viaWorker(worker, target, ip) {
  return requestText(`${worker}/api/page?u=${encodeURIComponent(target)}&ip=${encodeURIComponent(ip)}`,
    { timeout: 7000, minLen: 300, needIp: ip })
}

async function page(url, ip) {
  const hdr = url.includes('maxmind') ? MM_HDR() : HTML_HDR()
  for (let i = 0; i < 2; i++) {
    const t = await requestText(url, { timeout: 5000, minLen: 800, needIp: ip, headers: hdr })
    if (t && !t.slice(0, 3000).toLowerCase().includes('just a moment')) return t
    await sleep(200 * (i + 1))
  }
  return null
}

async function viaRelay(url, ip) {
  const out = await Promise.all(relays(url).slice(0, 2).map(u =>
    requestText(u, { timeout: 5000, minLen: 400, needIp: ip })))
  return out.find(Boolean) || null
}

async function getSl(ip, worker) {
  const c = memGet('sl:' + ip, SL_TTL)
  if (c) return c
  let t = null, src = 'none'
  if (worker) { t = await viaWorker(worker, SL_PAGE(ip), ip); if (t) src = 'worker' }
  if (!t) { t = await page(SL_PAGE(ip), ip); if (t) src = 'direct' }
  if (!t) { t = await viaRelay(SL_PAGE(ip), ip); if (t) src = 'relay' }
  const out = [t ? parseSl(t) : null, t ? src : 'none']
  if (out[0]) memSet('sl:' + ip, out)
  return out
}

async function getI2l(ip, worker) {
  const c = memGet('i2l:' + ip, SL_TTL)
  if (c) return c
  let t = null, src = 'none'
  if (worker) { t = await viaWorker(worker, I2L_PAGE(ip), ip); if (t) src = 'worker' }
  if (!t) { t = await page(I2L_PAGE(ip), ip); if (t) src = 'direct' }
  if (!t) { t = await viaRelay(I2L_PAGE(ip), ip); if (t) src = 'relay' }
  const out = [t ? parseI2l(t) : null, t ? src : 'none']
  if (out[0]) memSet('i2l:' + ip, out)
  return out
}

const json = b => new Response(JSON.stringify(b), { status: 200, headers: {
  'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' } })

const timed = (pr, ms) => Promise.race([pr.catch(() => null), sleep(ms).then(() => null)])

// ---------- মূল ----------
async function run(request) {
  const t0 = Date.now()

  let body = {}
  try { body = (await request.json()) || {} } catch { return json({ ...blank(''), verdict: 'ERROR', reasons: 'bad body' }) }

  const rec = blank(String(body.proxy || ''))
  const worker = normWorker(body.worker)
  const key = String(body.key || '').trim()
  const budget = Math.min(Math.max(Number(body.timeout) || 8, 4), 20)
  const p = parseProxy(rec.proxy)
  if (!p) return json({ ...rec, verdict: 'ERROR', reasons: 'invalid proxy' })

  try {
    const got = await exitIp(p, budget)
    if (!got) return json({ ...rec, verdict: 'DEAD', reasons: 'no exit IP (http+socks5 failed)',
                            secs: +((Date.now() - t0) / 1000).toFixed(1) })
    rec.ip = got.ip
    rec.scheme = got.scheme

    const hit = memGet('res:' + rec.ip, RES_TTL)
    if (hit) return json({ ...hit, proxy: rec.proxy, secs: +((Date.now() - t0) / 1000).toFixed(1) })

    const wait = budget * 1000
    const [slR, i2lR, mm] = await Promise.all([
      timed(getSl(rec.ip, worker), wait),
      timed(getI2l(rec.ip, worker), wait),
      timed(mmInfo(rec.ip), wait)
    ])

    const [sl, ssrc] = slR || [null, 'none']
    const [i2l, isrc] = i2lR || [null, 'none']
    rec.sl_src = ssrc
    rec.i2l_src = isrc
    rec.src = `${ssrc}/${isrc}`

    const [vs, rs] = slVerdict(sl)
    const [vi, ri] = i2lVerdict(i2l)
    let verdict = 'UNKNOWN'
    let extra = ''
    if (vs === 'FAIL' || vi === 'FAIL') verdict = 'FAIL'
    else if (vs === 'PASS' && vi === 'PASS') verdict = 'PASS'

    rec.mm_ct = (mm && mm.ct) || ''
    rec.ct_src = rec.mm_ct ? 'maxmind' : ''
    rec.mm_asn = (mm && mm.asn) || ''
    rec.mm_asnorg = (mm && mm.asnorg) || ''
    rec.mm_isp = (mm && mm.isp) || ''
    rec.mm_org = (mm && mm.org) || ''
    rec.mm_lat = (mm && mm.lat) || ''
    rec.mm_lon = (mm && mm.lon) || ''
    rec.mm_net = (mm && mm.net) || ''
    rec.sl_vpn = (sl && sl.vpn) || ''
    rec.sl_rproxy = (sl && sl.rproxy) || ''
    rec.sl_dc = (sl && sl.dc) || ''
    rec.i2l_anon = (i2l && i2l.anon) || ''
    rec.i2l_fraud = (i2l && i2l.fraud) || ''
    rec.i2l_seen = (i2l && i2l.seen) || ''

    if (verdict === 'UNKNOWN' && key && (!sl || !i2l)) {
      const a = await timed(ipapiIs(rec.ip, key), 5000)
      const av = apiVerdict(a)
      if (av) { verdict = av[0]; extra = ' | ' + av[1] }
      rec.api_flags = a ? `vpn:${+a.is_vpn} dc:${+a.is_datacenter} proxy:${+a.is_proxy} tor:${+a.is_tor} mobile:${+a.is_mobile} abuser:${+a.is_abuser}` : ''
    }

    rec.verdict = verdict
    rec.reasons = `scam: ${rs} | ip2loc: ${ri}${extra}`
    rec.secs = +((Date.now() - t0) / 1000).toFixed(1)

    if (verdict !== 'UNKNOWN') memSet('res:' + rec.ip, rec)
    return json(rec)
  } catch (e) {
    return json({ ...rec, verdict: 'ERROR', reasons: `${e.name}: ${String(e.message).slice(0, 100)}` })
  }
}

// ---------- ডায়াগনস্টিক ----------
async function probe(request) {
  const q = new URL(request.url).searchParams
  const raw = q.get('proxy') || ''
  const p = parseProxy(raw)
  if (!p) return json({ error: 'invalid proxy', got: raw })
  const t0 = Date.now()
  const out = { host: p.host, port: p.port, scheme: p.scheme || 'http', hasAuth: !!p.user }
  try {
    const s = await openTcp(p.host, p.port, 8000)
    out.tcp = 'ok'
    s.destroy()
  } catch (e) {
    out.tcpErr = `${e.name}: ${e.message}`
    out.ms = Date.now() - t0
    return json(out)
  }
  try {
    const t = await tunnel(p, 'api.ipify.org', 443, 8000)
    out.tunnel = 'ok'
    try {
      const plain = await requestText('http://checkip.amazonaws.com/', { proxy: p, timeout: 8000 })
      out.plainHttp = plain ? 'ok :: ' + plain.trim().slice(0, 40) : 'fail'
    } catch (e) { out.plainHttp = 'err ' + e.name }
    try {
      const tls = await tlsWrap(t, 'api.ipify.org')
      out.tls = 'ok'
      const r = await rawRequest(tls, { host: 'api.ipify.org', path: '/?format=json',
                                        headers: JSON_HDR, timeout: 8000 })
      out.https = r ? `status ${r.status} :: ${r.body.toString().slice(0, 60)}` : 'no response'
    } catch (e) { out.tlsErr = `${e.name}: ${e.message}` }
  } catch (e) {
    out.tunnelErr = `${e.name}: ${e.message}`
  }
  out.ms = Date.now() - t0
  return json(out)
}

async function pageProxy(request) {
  const sp = new URL(request.url).searchParams
  const target = String(sp.get('u') || '')
  const ip = validIp(sp.get('ip') || '')
  if (!ALLOW.test(target) || !ip) return new Response('bad request', { status: 400, headers: CORS })
  const t = await page(target, ip)
  if (!t) return new Response('', { status: 502, headers: CORS })
  return new Response(t, { status: 200, headers: {
    ...CORS, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } })
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url)
    if (pathname === '/api/check') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
      if (request.method === 'POST') return run(request)
      const sp = new URL(request.url).searchParams
      if (sp.has('probe')) return probe(request)
      const node = typeof process !== 'undefined' ? process.version : 'n/a'
      return json(sp.has('health') ? { ok: true, node, ct: 'maxmind-batch', rt: 'sockets' } : { ok: true })
    }
    if (pathname === '/api/page') return pageProxy(request)
    if (pathname === '/api/probe') return probe(request)
    return env.ASSETS.fetch(request)
  }
}
