const FN = '/api/check'
const HARD_MS = 60000
const KEY_LS = 'pc_key'

const $ = s => document.querySelector(s)
const list = $('#list')

let queue = [], results = new Map(), running = false, next = 0, done = 0
let counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, DEAD: 0, ERROR: 0 }
let penalty = 0, n429 = 0, t0 = 0
let lastRender = 0, renderQueued = false
let filter = null
const copied = new Set()

const rnd = (a, b) => a + Math.random() * (b - a)
const sleep = ms => new Promise(r => setTimeout(r, ms))

const LABEL = { PASS: 'PASS', FAIL: 'FAIL', inc: 'অসম্পূর্ণ' }

const MATCH = {
  PASS: r => U(r.verdict) === 'PASS',
  FAIL: r => U(r.verdict) === 'FAIL',
  UNKNOWN: r => U(r.verdict) === 'UNKNOWN',
  DEAD: r => U(r.verdict) === 'DEAD',
  ERROR: r => U(r.verdict) === 'ERROR',
  'res-yes': r => U(r.sl_rproxy) === 'YES',
  'res-no': r => U(r.sl_rproxy) === 'NO',
  cable: r => r.mm_ct === 'Cable/DSL',
  cell: r => r.mm_ct === 'Cellular',
  inc: r => !!r.ip && (!r.mm_ct || U(r.verdict) === 'UNKNOWN')
}

const isInc = r => !!r.ip && (!r.mm_ct || U(r.verdict) === 'UNKNOWN')

function parseProxy(line) {
  const raw = String(line || '').trim()
  if (!raw || raw.startsWith('#')) return null
  let body = raw
  const m = body.match(/^(https?|socks5h?|socks4a?):\/\//i)
  if (m) body = body.slice(m[0].length)
  if (body.includes('@')) body = body.slice(body.lastIndexOf('@') + 1)
  const parts = body.split(':')
  if (parts.length < 2 || !/^\d+$/.test(parts[1])) return null
  return { raw }
}

function readList() {
  const seen = new Set(), out = []
  for (const line of $('#proxies').value.split(/\r?\n/)) {
    const p = parseProxy(line)
    if (p && !seen.has(p.raw)) { seen.add(p.raw); out.push(p) }
  }
  return out
}

$('#proxies').addEventListener('input', () => { $('#parsed').textContent = `বৈধ: ${readList().length}` })

$('#file').addEventListener('change', async e => {
  const f = e.target.files[0]
  if (!f) return
  $('#proxies').value = await f.text()
  $('#parsed').textContent = `বৈধ: ${readList().length}`
})

$('#key').value = localStorage.getItem(KEY_LS) || ''
$('#key').addEventListener('change', () => localStorage.setItem(KEY_LS, $('#key').value.trim()))

const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
const U = v => String(v ?? '').trim().toUpperCase()

function norm(v) {
  if (v === true) return 'YES'
  if (v === false) return 'NO'
  const s = String(v ?? '').trim()
  if (!s) return ''
  const u = s.toUpperCase()
  if (u === 'TRUE' || u === 'YES' || u === 'Y' || u === '1') return 'YES'
  if (u === 'FALSE' || u === 'NO' || u === 'N' || u === '0') return 'NO'
  return s
}

const isYes = v => U(v) === 'YES'

const BANDS = [
  [15,  'অতি পরিষ্কার'],
  [25,  'বিশুদ্ধ'],
  [40,  'নিরপেক্ষ'],
  [70,  'সামান্য ঝুঁকি'],
  [101, 'চরম ঝুঁকি']
]

const val = v => isYes(v) ? `<b class="y">${esc(v)}</b>` : U(v) === 'NO' ? `<b class="n">${esc(v)}</b>` : esc(v || '—')
const kv = (k, v) => `<span class="kv">${k}: ${v}</span>`

function riskOf(r) {
  let s = 6
  if (isYes(r.sl_dc)) s += 28
  if (isYes(r.sl_vpn) || isYes(r.sl_rproxy)) s += 24
  if (isYes(r.i2l_anon)) s += 22
  const f = Number(r.i2l_fraud)
  if (Number.isFinite(f)) s = Math.round(s * 0.55 + f * 0.45)
  return Math.max(0, Math.min(100, s))
}

function ipTypeOf(r) {
  if (isYes(r.sl_vpn) || isYes(r.sl_rproxy) || isYes(r.i2l_anon)) return 'VPN / Proxy'
  if (isYes(r.sl_dc)) return 'Data Center'
  if (r.mm_ct === 'Cellular') return 'Cellular'
  if (r.mm_ct === 'Cable/DSL') return 'Residential'
  return 'Unknown'
}

function sharedOf(r) {
  let s = 0
  if (isYes(r.sl_dc)) s += 3
  if (isYes(r.sl_vpn) || isYes(r.sl_rproxy)) s += 2
  if (isYes(r.i2l_anon)) s += 4
  if (Number(r.i2l_fraud) >= 25) s += 1
  if (s <= 1) return '1 - 10 (Excellent)'
  if (s <= 4) return '11 - 30 (Good)'
  if (s <= 7) return '31 - 100 (Moderate)'
  return '100+ (Crowded)'
}

const srcBadge = s => `<span class="src ${!s || s === 'none' ? 'b' : ''}">${esc(s || 'none')}</span>`

const STAGES = { exit: 'exit', pages: 'pages', retry: 'retry', done: 'done', parse: 'parse', client: 'client', http: 'http' }

function card(r) {
  const v = U(r.verdict) || 'UNKNOWN'
  const vcls = v === 'PASS' ? 'pass' : v === 'FAIL' ? 'fail' : v === 'UNKNOWN' ? 'unk' : 'dead'
  const isCopied = copied.has(r.proxy)

  const head = `<div class="ihead">
      <span class="pv">${esc(r.proxy)}</span>
      <span class="vd ${vcls}">${esc(v)}</span>
      ${r.ip ? `<span class="pip">${esc(r.ip)}</span>` : ''}
      <span class="srcb">sl ${srcBadge(r.sl_src)}</span>
      <span class="srcb">i2l ${srcBadge(r.i2l_src)}</span>
      ${r.stage ? `<span class="stg">${esc(STAGES[r.stage] || r.stage)}</span>` : ''}
      <button class="cp${isCopied ? ' ok' : ''}" data-p="${esc(r.proxy)}" title="শুধু প্রক্সি কপি">${isCopied ? '✓ কপি হয়েছে' : 'কপি'}</button>
      <span class="secs">${esc(r.secs)}s</span>
    </div>`

  if (!r.ip) {
    return `<div class="item${isCopied ? ' copied' : ''}">${head}
      <div class="idet">${kv('Reasons', esc(r.reasons || '—'))}</div>
    </div>`
  }

  const it = ipTypeOf(r)
  const native = it === 'Residential' || it === 'Cellular' ? 'Native IP' : 'Non-Native IP'
  const n = riskOf(r)
  const band = BANDS.find(x => n < x[0]) || BANDS[4]
  const ipLink = `<a class="lnk" href="https://ping0.cc/ip/${esc(r.ip)}" target="_blank" rel="noopener">${esc(r.ip)}</a>`

  return `<div class="item${isCopied ? ' copied' : ''}">${head}
    <div class="idet">
      ${kv('IP', ipLink)}
      ${kv('Anonymizing VPN', val(r.sl_vpn))}
      ${kv('Residential Proxy', val(r.sl_rproxy))}
      ${kv('Datacenter', val(r.sl_dc))}
      ${kv('Anonymous Proxy', val(r.i2l_anon))}
      ${kv('Last Seen', esc(r.i2l_seen || '-'))}
      ${kv('Fraud Score', esc(r.i2l_fraud || '—'))}
      ${kv('Connection type', esc(r.mm_ct || '—'))}
      ${kv('CT Source', esc(r.ct_src || '—'))}
      ${kv('API flags', esc(r.api_flags || '—'))}
      ${kv('ASN', esc(r.mm_asn || '—'))}
      ${kv('ASN Owner', esc(r.mm_asnorg || '—'))}
      ${kv('Organization', esc(r.mm_org || r.mm_isp || '—'))}
      ${kv('Network', esc(r.mm_net || '—'))}
      ${kv('Longitude', esc(r.mm_lon || '—'))}
      ${kv('Latitude', esc(r.mm_lat || '—'))}
      ${kv('IP Type', esc(it))}
      ${kv('Risk Score', `${n}% ${band[1]}`)}
      ${kv('Native IP', esc(native))}
      ${kv('Shared Users Count', esc(sharedOf(r)))}
      ${r.reasons ? kv('Reasons', esc(r.reasons)) : ''}
    </div>
  </div>`
}

const all = () => [...results.values()]
const visible = () => {
  const rows = all().reverse()
  return filter ? rows.filter(MATCH[filter]) : rows
}

function render() {
  const now = Date.now()
  if (now - lastRender < 250) {
    if (!renderQueued) { renderQueued = true; setTimeout(() => { renderQueued = false; render() }, 260) }
    return
  }
  lastRender = now
  const rows = visible()
  $('#empty').style.display = rows.length ? 'none' : ''
  if (!rows.length) {
    $('#empty').innerHTML = filter
      ? `এই ফিল্টারে (<b>${esc(LABEL[filter])}</b>) এখনো কিছু নেই।`
      : 'লিস্ট বসিয়ে <b>শুরু</b> চাপুন — ফলাফল এখানে আসবে।'
  }
  list.innerHTML = rows.map(card).join('')
  if (filter) $('#f-count').textContent = `মোট ${rows.length} টি`
}

function setFilter(f) {
  filter = (filter === f) ? null : f
  for (const b of document.querySelectorAll('.st')) b.classList.toggle('on', b.dataset.f === filter)
  const bar = $('#fbar')
  bar.classList.toggle('on', !!filter)
  if (filter) $('#f-label').textContent = LABEL[filter]
  render()
  if (filter) list.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

for (const b of document.querySelectorAll('.st')) b.addEventListener('click', () => setFilter(b.dataset.f))
$('#f-all').addEventListener('click', () => { if (filter) setFilter(filter) })

async function copyText(t) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(t); return true }
  } catch {}
  try {
    const ta = document.createElement('textarea')
    ta.value = t
    ta.style.position = 'fixed'
    ta.style.top = '-1000px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus(); ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch { return false }
}

list.addEventListener('click', async e => {
  const btn = e.target.closest('.cp')
  if (!btn) return
  const p = btn.dataset.p
  const ok = await copyText(p)
  if (!ok) { alert('কপি করা যায়নি — ব্রাউজার অনুমতি দেয়নি।'); return }
  copied.add(p)
  const rec = results.get(p)
  if (rec) rec.copied = true
  btn.classList.add('ok')
  btn.textContent = '✓ কপি হয়েছে'
  const item = btn.closest('.item')
  if (item) item.classList.add('copied')
  stats()
})

function stats() {
  const el = Math.max((Date.now() - t0) / 1000, 0.001)
  let inc = 0
  for (const r of results.values()) if (isInc(r)) inc++
  $('#s-done').textContent = `${done}/${queue.length}`
  $('#s-pass').textContent = counts.PASS
  $('#s-fail').textContent = counts.FAIL
  $('#s-inc').textContent = inc
  $('#s-copied').textContent = copied.size
  $('#s-rate').textContent = Math.round(done / el * 60)
  $('#s-429').textContent = n429
  $('#s-el').textContent = Math.round(el) + 's'
  $('#prog').style.width = queue.length ? (done / queue.length * 100).toFixed(1) + '%' : '0'
  resCount()
  render()
}

function resCount() {
  const el = $('#rescount')
  if (!el) return
  const want = []
  if ($('#res-yes').checked) want.push('YES')
  if ($('#res-no').checked) want.push('NO')
  if (!want.length) { el.textContent = ''; return }
  const n = all().filter(r => want.includes(U(r.sl_rproxy))).length
  el.textContent = `নির্বাচিত: ${n} টি`
}

const errRec = (p, reason, ms, stage) => ({
  proxy: p.raw, scheme: '', ip: '', verdict: 'ERROR', reasons: reason, stage: stage || '',
  src: '', sl_src: 'none', i2l_src: 'none', ct_src: '',
  secs: +((Date.now() - ms) / 1000).toFixed(1),
  sl_vpn: '', sl_rproxy: '', sl_dc: '', i2l_anon: ''
})

async function checkOne(p) {
  const worker = $('#worker').value.trim()
  const key = $('#key').value.trim()
  const timeout = Math.min(Math.max(Number($('#timeout').value) || 12, 4), 25)
  const t = Date.now()

  for (let attempt = 0; attempt < 3; attempt++) {
    if (penalty > 0) await sleep(rnd(0, penalty))
    const ctl = new AbortController()
    const timer = setTimeout(() => ctl.abort(), HARD_MS)
    try {
      const res = await fetch(FN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy: p.raw, worker, key, timeout }),
        signal: ctl.signal
      })
      clearTimeout(timer)
      const raw = await res.text()
      let j = null
      try { j = JSON.parse(raw) } catch {}
      if (!j) {
        return errRec(p, `http ${res.status} ${raw.slice(0, 80).replace(/\s+/g, ' ')}`, t, 'http')
      }
      if (res.status === 429 || res.status >= 500) {
        n429++
        penalty = Math.min(penalty + 0.3, 5)
        if (attempt < 2) { await sleep(rnd(400, 1200) * (attempt + 1)); continue }
      }
      penalty = Math.max(0, penalty * 0.98)
      return {
        ...j,
        proxy: p.raw,
        verdict: U(j.verdict) || 'UNKNOWN',
        sl_vpn: norm(j.sl_vpn),
        sl_rproxy: norm(j.sl_rproxy),
        sl_dc: norm(j.sl_dc),
        i2l_anon: norm(j.i2l_anon),
        secs: j.secs ?? ((Date.now() - t) / 1000).toFixed(1)
      }
    } catch (e) {
      clearTimeout(timer)
      if (e.name === 'AbortError') {
        if (attempt < 1) { await sleep(300); continue }
        return errRec(p, `timeout ${Math.round(HARD_MS / 1000)}s`, t, 'client')
      }
      if (attempt < 2) { await sleep(500 * (attempt + 1)); continue }
      return errRec(p, e.name, t, 'client')
    }
  }
}

async function lane() {
  while (running) {
    const i = next++
    if (i >= queue.length) return
    const rec = await checkOne(queue[i])
    const prev = results.get(rec.proxy)
    if (prev && prev.verdict) counts[prev.verdict] = Math.max(0, (counts[prev.verdict] || 0) - 1)
    counts[rec.verdict] = (counts[rec.verdict] || 0) + 1
    results.set(rec.proxy, rec)
    done++
    stats()
  }
}

async function startRun(l) {
  queue = l; next = 0; done = 0
  penalty = 0; n429 = 0; t0 = Date.now(); running = true
  $('#empty').style.display = 'none'
  $('#start').disabled = true
  $('#recheck').disabled = true
  $('#stop').disabled = false
  stats()

  const conc = Math.min(Math.max(Number($('#conc').value) || 40, 1), 500)
  await Promise.all(Array.from({ length: conc }, lane))

  running = false
  $('#start').disabled = false
  $('#recheck').disabled = false
  $('#stop').disabled = true
  stats()
}

$('#start').addEventListener('click', () => {
  if (running) return
  const l = readList()
  if (!l.length) { alert('বৈধ প্রক্সি নেই।'); return }
  results = new Map()
  counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, DEAD: 0, ERROR: 0 }
  copied.clear()
  list.innerHTML = ''
  startRun(l)
})

$('#recheck').addEventListener('click', () => {
  if (running) return
  const rows = [...results.values()].filter(isInc)
  if (!rows.length) { alert('রি-চেক করার মতো অসম্পূর্ণ রেকর্ড নেই।'); return }
  for (const r of rows) results.delete(r.proxy)
  startRun(rows.map(r => ({ raw: r.proxy })))
})

$('#stop').addEventListener('click', () => { running = false })

$('#clear').addEventListener('click', () => {
  if (running) return
  $('#proxies').value = ''
  $('#parsed').textContent = ''
  list.innerHTML = ''
  results = new Map(); queue = []; done = 0
  counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, DEAD: 0, ERROR: 0 }
  copied.clear()
  if (filter) setFilter(filter)
  resCount()
  stats()
})

$('#test').addEventListener('click', async () => {
  try {
    const r = await fetch(FN + '?health=1')
    alert(`status ${r.status}\n${(await r.text()).slice(0, 300)}`)
  } catch (e) { alert('fetch fail: ' + e.name) }
})

function download(name, text, type = 'text/plain') {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 4000)
}

const passRows = () => all().filter(r => r.verdict === 'PASS')
const resRows = v => all().filter(r => U(r.sl_rproxy) === v)
const ctRows = v => all().filter(r => r.mm_ct === v)
const csvCell = v => `"${String(v ?? '').replace(/"/g, '""')}"`
const FIELDS = ['proxy', 'scheme', 'ip', 'verdict', 'reasons', 'stage', 'src', 'sl_src', 'i2l_src', 'ct_src',
                'sl_vpn', 'sl_rproxy', 'sl_dc', 'i2l_anon', 'i2l_fraud', 'i2l_seen', 'api_flags',
                'mm_ct', 'mm_asn', 'mm_asnorg', 'mm_isp', 'mm_org', 'mm_lat', 'mm_lon', 'mm_net', 'secs']

$('#dl-csv').addEventListener('click', () => download('all.csv',
  [FIELDS.join(','), ...all().map(r => FIELDS.map(f => csvCell(r[f])).join(','))].join('\n'), 'text/csv'))

$('#dl-good').addEventListener('click', () => download('good.txt', passRows().map(r => r.proxy).join('\n')))

$('#dl-cable').addEventListener('click', () => {
  const rows = ctRows('Cable/DSL')
  if (!rows.length) { alert('Cable/DSL টাইপের কোনো প্রক্সি নেই।'); return }
  download('cable_dsl.txt', rows.map(r => r.proxy).join('\n'))
})

$('#dl-cell').addEventListener('click', () => {
  const rows = ctRows('Cellular')
  if (!rows.length) { alert('Cellular টাইপের কোনো প্রক্সি নেই।'); return }
  download('cellular.txt', rows.map(r => r.proxy).join('\n'))
})

$('#dl-resyes').addEventListener('click', () => download('res_yes.txt', resRows('YES').map(r => r.proxy).join('\n')))
$('#dl-resno').addEventListener('click', () => download('res_no.txt', resRows('NO').map(r => r.proxy).join('\n')))

$('#dl-res').addEventListener('click', () => {
  const want = []
  if ($('#res-yes').checked) want.push('YES')
  if ($('#res-no').checked) want.push('NO')
  if (!want.length) { alert('আগে YES বা NO — অন্তত একটা টিক দিন।'); return }
  const rows = all().filter(r => want.includes(U(r.sl_rproxy)))
  if (!rows.length) { alert('এই সিলেকশনে কোনো প্রক্সি নেই।'); return }
  download('residential.txt', rows.map(r => r.proxy).join('\n'))
})

$('#res-yes').addEventListener('change', resCount)
$('#res-no').addEventListener('change', resCount)
