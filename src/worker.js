// সব ব্যাকএন্ড এক ফাইলে — কোনো আলাদা import নেই।
import { connect } from 'cloudflare:sockets'

const FRAUD_MAX = 20
const SEEN_OK = new Set(['', '-', '0'])
const ECHO_MIN = 4000
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
           '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
const HTML_HDR = { 'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                   'Accept-Language': 'en-US,en;q=0.9' }
const JSON_HDR = { 'User-Agent': UA, 'Accept': 'application/json,*/*;q=0.8' }

const SL_PAGE = ip => 'https://scamalytics.com/ip/' + encodeURIComponent(ip)
const I2L_PAGE = ip => 'https://www.ip2location.com/demo/' + encodeURIComponent(ip)
const MM_PAGE = ip => 'https://www.maxmind.com/en/geoip-web-services-demo/' + encodeURIComponent(ip)
const IP_ECHO = ['https://api.ipify.org?format=json', 'https://api64.ipify.org?format=json',
  'https://api.ipapi.is/', 'https://ipapi.co/ip/', 'https://ifconfig.me/all.json',
  'https://icanhazip.com/', 'https://checkip.amazonaws.com/']
const PRE = String.raw`\|\s*(?:-\s*\[[ xX]\]\s*)?\**\s*`
const SEEN_ALT = String.raw`\d+\s*(?:second|minute|hour|day|week|month|year)s?\s*ago`
const relays = u => ['https://r.jina.ai/' + u,
  'https://api.allorigins.win/raw?url=' + encodeURIComponent(u),
  'https://api.codetabs.com/v1/proxy/?quest=' + encodeURIComponent(u),
  'https://api.cors.lol/?url=' + encodeURIComponent(u),
  'https://corsproxy.io/?url=' + encodeURIComponent(u)]

const CT_TTL = 6 * 3600 * 1000
const ctMem = new Map()
const CT_RE = /"connection_type"\s*:\s*"([^"]+)"/i
const CT_ROW = /Connection\s*type[^A-Za-z]{0,40}(Cable\/DSL|Cellular|Corporate|Satellite)/i
const IPAPI = ip => 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,mobile,proxy,hosting'

const FIELDS = ['proxy', 'scheme', 'ip', 'verdict', 'reasons', 'src', 'sl_vpn', 'sl_rproxy',
                'sl_dc', 'i2l_anon', 'i2l_fraud', 'i2l_seen', 'mm_ct', 'mm_asn', 'mm_asnorg',
                'mm_isp', 'mm_org', 'mm_lat', 'mm_lon', 'mm_net', 'secs']
const blank = p => Object.fromEntries([...FIELDS.map(f => [f, '']), ['proxy', p]])
const rnd = (a, b) => a + Math.random() * (b - a)
const sleep = ms => new Promise(r => setTimeout(r, ms))
const TE = new TextEncoder()

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
    try { await this._reader.cancel() } catch {}
    try { this._reader.releaseLock() } catch {}
    try { this._writer.releaseLock() } catch {}
    this._dead = true
    this._h = { data: [], error: [], close: [] }
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
      if (buf.length > 3_000_000) return finish(null)
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
    if (cl > 3_000_000) return null
    const ab = await r.arrayBuffer()
    if (ab.byteLength > 3_000_000) return null
    return { status: r.status, headers: Object.fromEntries(r.headers), body: Buffer.from(ab) }
  } catch { return null } finally { clearTimeout(timer) }
}

async function requestText(url, opts = {}) {
  const { proxy, timeout = 6000, headers = HTML_HDR, minLen = 0, needIp = '', redirects = 4 } = opts
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

// ---------- HTML → টেক্সট ----------
const deTag = x => String(x || '').replace(/<[^>]+>/g, ' ')
  .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#39;/g, "'")
  .replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')

const textify = h => deTag(String(h || '')
  .replace(/<!--[\s\S]*?-->/g, ' ').replace(/<script[\s\S]*?<\/script>/gi, ' ')
  .replace(/<style[\s\S]*?<\/style>/gi, ' ')
  .replace(/<br\s*\/?>|<\/tr>|<\/th>|<\/td>|<\/div>|<\/p>|<\/h\d>|<\/li>/gi, '\n'))

const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function htmlVal(txt, label, window = 90, pattern = '(Yes|No|N/A|True|False)') {
  const re = new RegExp(escRe(label), 'gi')
  let m
  while ((m = re.exec(txt))) {
    const seg = txt.slice(m.index + m[0].length, m.index + m[0].length + window)
    const v = seg.match(new RegExp(pattern, 'i'))
    if (v) return v[1].toUpperCase()
  }
  return ''
}

const ynField = (t, label) => {
  const m = t.match(new RegExp(PRE + escRe(label) + String.raw`\s*\**\s*\|\s*\**\s*(Yes|No|True|False|N/A)\s*\**\s*\|`, 'i'))
  return m ? m[1].toUpperCase() : ''
}

function parseSl(t) {
  if (!t) return null
  const x = textify(t)
  const o = { vpn: htmlVal(x, 'Anonymizing VPN') || ynField(t, 'Anonymizing VPN'),
              rproxy: htmlVal(x, 'Residential Proxy') || ynField(t, 'Residential Proxy'),
              dc: htmlVal(x, 'Datacenter') || ynField(t, 'Datacenter') }
  return (o.vpn || o.dc || o.rproxy) ? o : null
}

function i2lText(txt, label, pattern = '[^\\n]{0,40}') {
  const re = new RegExp(escRe(label), 'gi')
  let m
  while ((m = re.exec(txt))) {
    const seg = txt.slice(m.index + m[0].length, m.index + m[0].length + 120)
    const v = seg.match(new RegExp('\\n\\s*(' + pattern + ')'))
    if (v) return v[1].replace(/\s+/g, ' ').trim()
  }
  return ''
}

const i2lMd = (t, label) => {
  const m = t.match(new RegExp(PRE + escRe(label) + String.raw`\s*\**\s*\|\s*\**\s*([^|\n]{0,80}?)\s*\**\s*\|`, 'i'))
  return m ? m[1].replace(/\s+/g, ' ').trim() : ''
}

function parseI2l(t) {
  if (!t) return null
  const x = textify(t)
  const o = { anon: i2lText(x, 'Anonymous Proxy', 'Yes|No|N/A') || i2lMd(t, 'Anonymous Proxy'),
              seen: i2lText(x, 'Last Seen', '-|' + SEEN_ALT + '|\\d+\\s*days?') || i2lMd(t, 'Last Seen'),
              fraud: i2lText(x, 'Fraud Score', '\\d{1,3}|-') || i2lMd(t, 'Fraud Score') }
  if (!(o.anon || o.fraud || o.seen)) {
    const f = t.match(/"fraud_score"\s*:\s*(\d{1,3})/i)
    const p = t.match(/"is_proxy"\s*:\s*(true|false)/i)
    if (!f && !p) return null
    return { anon: p ? (p[1].toLowerCase() === 'true' ? 'YES' : 'NO') : '', seen: '', fraud: f ? f[1] : '' }
  }
  return o
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

// ---------- MaxMind ----------
function normCt(v) {
  const s = String(v || '').toLowerCase()
  if (s.includes('cable') || s.includes('dsl')) return 'Cable/DSL'
  if (s.includes('cell')) return 'Cellular'
  if (s.includes('corp')) return 'Corporate'
  if (s.includes('sat')) return 'Satellite'
  return ''
}

const js = (s, k) => { const m = String(s || '').match(new RegExp('"' + k + '"\\s*:\\s*"([^"]*)"', 'i')); return m ? m[1] : '' }
const jn = (s, k) => { const m = String(s || '').match(new RegExp('"' + k + '"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)', 'i')); return m ? m[1] : '' }

function parseMm(t, ip) {
  if (!t || !t.includes(ip)) return null
  const m = t.match(CT_RE) || t.match(CT_ROW)
  const ct = normCt(m && m[1])
  const asn = jn(t, 'autonomous_system_number')
  if (!ct && !asn) return null
  return {
    ct,
    asn: asn ? 'AS' + asn : '',
    asnorg: js(t, 'autonomous_system_organization'),
    isp: js(t, 'isp'),
    org: js(t, 'organization'),
    lat: jn(t, 'latitude'),
    lon: jn(t, 'longitude'),
    net: js(t, 'network')
  }
}

async function mmInfo(ip) {
  const hit = ctMem.get(ip)
  if (hit && Date.now() - hit.t < CT_TTL) return hit.v
  for (let i = 0; i < 2; i++) {
    let t = await page(MM_PAGE(ip), ip)
    if (!t) t = await viaRelay(MM_PAGE(ip), ip)
    if (t) {
      const v = parseMm(t, ip)
      if (v) { ctMem.set(ip, { v, t: Date.now() }); return v }
      return null
    }
    await sleep(rnd(300, 700))
  }
  return null
}

async function ipapiType(ip) {
  const t = await requestText(IPAPI(ip), { timeout: 3500, headers: JSON_HDR })
  if (!t) return ''
  try {
    const j = JSON.parse(t)
    if (j.status !== 'success') return ''
    if (j.mobile) return 'Cellular'
    if (!j.hosting && !j.proxy) return 'Cable/DSL'
  } catch {}
  return ''
}

// ---------- ধাপ ----------
const workerUrl = (w, site, ip) => `${w}/?site=${site}&ip=${encodeURIComponent(ip)}`

async function tryEcho(p, urls, timeout) {
  for (const url of urls) {
    const t = await requestText(url, { proxy: p, timeout, headers: JSON_HDR })
    if (!t) continue
    let ip = ''
    try { const j = JSON.parse(t); ip = validIp(j.ip || j.ipAddress || j.ip_addr || '') } catch {}
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
  const urls = [...IP_ECHO].sort(() => Math.random() - 0.5)
  const per = Math.min(12000, Math.max(ECHO_MIN, Math.round(budget * 500)))
  const socksFirst = p.scheme === 'socks5' || p.scheme === 'socks4'
  const A = socksFirst ? 'socks5' : 'http'
  const B = socksFirst ? 'http' : 'socks5'
  const got = await firstOk([
    tryEcho({ ...p, scheme: A }, urls.slice(0, 1), per).then(ip => ip && { ip, scheme: A }),
    tryEcho({ ...p, scheme: B }, urls.slice(1, 2), per).then(ip => ip && { ip, scheme: B })
  ])
  if (got) return got
  const rest = await tryEcho({ ...p, scheme: A }, urls.slice(2, 4), per)
  return rest ? { ip: rest, scheme: A } : null
}

async function fetchWorker(w, site, ip) {
  for (let i = 0; i < 2; i++) {
    const r = await requestText(workerUrl(w, site, ip), { timeout: 3000, headers: JSON_HDR })
    if (r) {
      try {
        const j = JSON.parse(r)
        return j && Object.values(j).some(v => String(v).trim()) ? j : null
      } catch { return null }
    }
    await sleep(rnd(250, 600) * (i + 1))
  }
  return null
}

async function page(url, ip) {
  for (let i = 0; i < 2; i++) {
    const t = await requestText(url, { timeout: 4500, minLen: 800, needIp: ip })
    if (t && !t.slice(0, 3000).toLowerCase().includes('just a moment')) return t
    await sleep(300 * (i + 1))
  }
  return null
}

async function viaRelay(url, ip) {
  const out = await Promise.all(relays(url).map(u =>
    requestText(u, { timeout: 4500, minLen: 400, needIp: ip })))
  return out.find(Boolean) || null
}

async function getSl(ip, w) {
  if (w) { const p = parseWSl(await fetchWorker(w, 'sl', ip)); if (p) return [p, 'worker'] }
  let t = await page(SL_PAGE(ip), ip)
  if (t) return [parseSl(t), 'direct']
  t = await viaRelay(SL_PAGE(ip), ip)
  return [t ? parseSl(t) : null, t ? 'relay' : 'none']
}

async function getI2l(ip, w) {
  if (w) { const p = parseWI2l(await fetchWorker(w, 'i2l', ip)); if (p) return [p, 'worker'] }
  let t = await page(I2L_PAGE(ip), ip)
  if (t) return [parseI2l(t), 'direct']
  t = await viaRelay(I2L_PAGE(ip), ip)
  return [t ? parseI2l(t) : null, t ? 'relay' : 'none']
}

const json = b => new Response(JSON.stringify(b), { status: 200, headers: {
  'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' } })

// ---------- ডায়াগনস্টিক ----------
async function probe(request) {
  const q = new URL(request.url).searchParams
  const p = parseProxy(q.get('proxy') || '')
  if (!p) return json({ error: 'invalid proxy', got: q.get('proxy') || '' })
  const t0 = Date.now(), out = { host: p.host, port: p.port, scheme: p.scheme || 'http' }
  try {
    const s = await openTcp(p.host, p.port, 8000)
    out.tcp = 'ok'
    try {
      const t = await tunnel(p, 'api.ipify.org', 443, 8000)
      out.tunnel = 'ok'
      const tls = await tlsWrap(t, 'api.ipify.org')
      out.tls = 'ok'
      const r = await rawRequest(tls, { host: 'api.ipify.org', path: '/?format=json',
                                        headers: JSON_HDR, timeout: 8000 })
      out.http = r ? `status ${r.status} :: ${r.body.toString().slice(0, 80)}` : 'no response'
    } catch (e) { out.tunnelErr = `${e.name}: ${e.message}` }
  } catch (e) { out.tcpErr = `${e.name}: ${e.message}` }
  out.ms = Date.now() - t0
  return json(out)
}

async function run(request) {
  const t0 = Date.now()

  let body = {}
  try { body = (await request.json()) || {} } catch { return json({ ...blank(''), verdict: 'ERROR', reasons: 'bad body' }) }

  const rec = blank(String(body.proxy || ''))
  const worker = String(body.worker || '').trim().replace(/\/+$/, '')
  const budget = Math.min(Math.max(Number(body.timeout) || 8, 4), 20)
  const p = parseProxy(rec.proxy)
  if (!p) return json({ ...rec, verdict: 'ERROR', reasons: 'invalid proxy' })

  try {
    const got = await exitIp(p, budget)
    if (!got) return json({ ...rec, verdict: 'DEAD', reasons: 'no exit IP (http+socks5 failed)',
                            secs: +((Date.now() - t0) / 1000).toFixed(1) })
    rec.ip = got.ip
    rec.scheme = got.scheme

    const settled = await Promise.race([
      Promise.allSettled([getSl(rec.ip, worker), getI2l(rec.ip, worker), mmInfo(rec.ip)]),
      sleep(budget * 1000).then(() => null)
    ])
    const ok = i => !!(settled && settled[i] && settled[i].status === 'fulfilled')
    const [sl, ssrc] = ok(0) ? settled[0].value : [null, 'none']
    const [i2l, isrc] = ok(1) ? settled[1].value : [null, 'none']
    let mm = ok(2) ? settled[2].value : null
    rec.src = `${ssrc}/${isrc}`

    const [vs, rs] = slVerdict(sl)
    const [vi, ri] = i2lVerdict(i2l)
    let verdict = 'UNKNOWN'
    if (vs === 'FAIL' || vi === 'FAIL') verdict = 'FAIL'
    else if (vs === 'PASS' && vi === 'PASS') verdict = 'PASS'

    if (!mm || !mm.ct) {
      const fb = await ipapiType(rec.ip).catch(() => '')
      if (fb) mm = { ...(mm || {}), ct: fb, fb: '1' }
    }

    return json({ ...rec, verdict, reasons: `scam: ${rs} | ip2loc: ${ri}`,
      sl_vpn: sl?.vpn || '', sl_rproxy: sl?.rproxy || '', sl_dc: sl?.dc || '',
      i2l_anon: i2l?.anon || '', i2l_fraud: i2l?.fraud || '', i2l_seen: i2l?.seen || '',
      mm_ct: mm?.ct || '', mm_fb: mm?.fb || '', mm_asn: mm?.asn || '',
      mm_asnorg: mm?.asnorg || '', mm_isp: mm?.isp || '', mm_org: mm?.org || '',
      mm_lat: mm?.lat || '', mm_lon: mm?.lon || '', mm_net: mm?.net || '',
      secs: +((Date.now() - t0) / 1000).toFixed(1) })
  } catch (e) {
    return json({ ...rec, verdict: 'ERROR', reasons: `${e.name}: ${String(e.message).slice(0, 100)}` })
  }
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
      return json(sp.has('health') ? { ok: true, node, ct: 'maxmind+ipapi', rt: 'sockets' } : { ok: true })
    }
    return env.ASSETS.fetch(request)
  }
}