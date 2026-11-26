const FN = '/api/check'
const HARD_MS = 30000

const $ = s => document.querySelector(s)
const list = $('#list')

let queue = [], results = new Map(), running = false, next = 0, done = 0
let counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, DEAD: 0, ERROR: 0 }
let penalty = 0, n429 = 0, t0 = 0
let lastRender = 0, renderQueued = false

const rnd = (a, b) => a + Math.random() * (b - a)
const sleep = ms => new Promise(r => setTimeout(r, ms))

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

const esc = s => String(s || '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
const U = v => String(v || '').trim().toUpperCase()

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

function card(r) {
  const v = U(r.verdict) || 'UNKNOWN'
  const vcls = v === 'PASS' ? 'pass' : v === 'FAIL' ? 'fail' : v === 'UNKNOWN' ? 'unk' : 'dead'
  const it = ipTypeOf(r)
  const native = it === 'Residential' || it === 'Cellular' ? 'Native IP' : 'Non-Native IP'
  const n = riskOf(r)
  const band = BANDS.find(x => n < x[0]) || BANDS[4]
  const blocked = !r.src || r.src.split('/')[0] === 'none'
  const ipLink = r.ip ? `<a class="lnk" href="https://ping0.cc/ip/${esc(r.ip)}" target="_blank" rel="noopener">${esc(r.ip)}</a>` : '—'

  return `<div class="item">
    <div class="ihead">
      <span class="pv">${esc(r.proxy)}</span>
      <span class="vd ${vcls}">${esc(v)}</span>
      ${r.ip ? `<span class="pip">${esc(r.ip)}</span>` : ''}
      <span class="src ${blocked ? 'b' : ''}">${blocked ? 'blocked' : 'live'}</span>
      <span class="secs">${esc(r.secs)}s</span>
    </div>
    <div class="idet">
      ${kv('IP', ipLink)}
      ${kv('Anonymizing VPN', val(r.sl_vpn))}
      ${kv('Residential Proxy', val(r.sl_rproxy))}
      ${kv('Datacenter', val(r.sl_dc))}
      ${kv('Anonymous Proxy', val(r.i2l_anon))}
      ${kv('Last Seen', esc(r.i2l_seen || '-'))}
      ${kv('Fraud Score', esc(r.i2l_fraud || '—'))}
      ${kv('Connection type', esc(r.mm_ct || '—'))}
      ${kv('ASN', esc(r.mm_asn || '—'))}
      ${kv('ASN Owner', esc(r.mm_asnorg || '—'))}
      ${kv('Organization', esc(r.mm_org || r.mm_isp || '—'))}
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

function render() {
  const now = Date.now()
  if (now - lastRender < 250) {
    if (!renderQueued) { renderQueued = true; setTimeout(() => { renderQueued = false; render() }, 260) }
    return
  }
  lastRender = now
  const rows = [...results.values()].reverse()
  $('#empty').style.display = rows.length ? 'none' : ''
  list.innerHTML = rows.map(card).join('')
}

function stats() {
  const el = Math.max((Date.now() - t0) / 1000, 0.001)
  let resy = 0, resn = 0, cable = 0, cell = 0
  for (const r of results.values()) {
    if (isYes(r.sl_rproxy)) resy++
    else if (U(r.sl_rproxy) === 'NO') resn++
    if (r.mm_ct === 'Cable/DSL') cable++
    else if (r.mm_ct === 'Cellular') cell++
  }
  $('#s-done').textContent = `${done}/${queue.length}`
  $('#s-pass').textContent = counts.PASS
  $('#s-fail').textContent = counts.FAIL
  $('#s-unk').textContent = counts.UNKNOWN
  $('#s-dead').textContent = counts.DEAD
  $('#s-err').textContent = counts.ERROR
  $('#s-resy').textContent = resy
  $('#s-resn').textContent = resn
  $('#s-cable').textContent = cable
  $('#s-cell').textContent = cell
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

async function checkOne(p) {
  const worker = $('#worker').value.trim()
  const timeout = Math.min(Math.max(Number($('#timeout').value) || 8, 4), 12)
  const t = Date.now()

  for (let attempt = 0; attempt < 3; attempt++) {
    if (penalty > 0) await sleep(rnd(0, penalty))
    const ctl = new AbortController()
    const timer = setTimeout(() => ctl.abort(), HARD_MS)
    try {
      const res = await fetch(FN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy: p.raw, worker, timeout }),
        signal: ctl.signal
      })
      clearTimeout(timer)
      const raw = await res.text()
      let j = null
      try { j = JSON.parse(raw) } catch {}
      if (!j) {
        return { proxy: p.raw, scheme: '', ip: '', verdict: 'ERROR',
                 reasons: `http ${res.status} ${raw.slice(0, 80).replace(/\s+/g, ' ')}`,
                 src: '', secs: 0, sl_vpn: '', sl_rproxy: '', sl_dc: '', i2l_anon: '' }
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
      if (attempt < 2) { await sleep(500 * (attempt + 1)); continue }
      return { proxy: p.raw, scheme: '', ip: '', verdict: 'ERROR', reasons: e.name,
               src: '', secs: 0, sl_vpn: '', sl_rproxy: '', sl_dc: '', i2l_anon: '' }
    }
  }
}

async function lane() {
  while (running) {
    const i = next++
    if (i >= queue.length) return
    const rec = await checkOne(queue[i])
    counts[rec.verdict] = (counts[rec.verdict] || 0) + 1
    results.set(rec.proxy, rec)
    done++
    stats()
  }
}

$('#start').addEventListener('click', async () => {
  if (running) return
  const l = readList()
  if (!l.length) { alert('বৈধ প্রক্সি নেই।'); return }

  queue = l; results = new Map(); next = 0; done = 0
  counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, DEAD: 0, ERROR: 0 }
  penalty = 0; n429 = 0; t0 = Date.now(); running = true
  list.innerHTML = ''
  $('#empty').style.display = 'none'

  $('#start').disabled = true
  $('#stop').disabled = false
  stats()

  const conc = Math.min(Math.max(Number($('#conc').value) || 40, 1), 500)
  await Promise.all(Array.from({ length: conc }, lane))

  running = false
  $('#start').disabled = false
  $('#stop').disabled = true
  stats()
})

$('#stop').addEventListener('click', () => { running = false })

$('#clear').addEventListener('click', () => {
  if (running) return
  $('#proxies').value = ''
  $('#parsed').textContent = ''
  list.innerHTML = ''
  results = new Map(); queue = []; done = 0
  counts = { PASS: 0, FAIL: 0, UNKNOWN: 0, DEAD: 0, ERROR: 0 }
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

const all = () => [...results.values()]
const passRows = () => all().filter(r => r.verdict === 'PASS')
const resRows = v => all().filter(r => U(r.sl_rproxy) === v)
const csvCell = v => `"${String(v ?? '').replace(/"/g, '""')}"`
const FIELDS = ['proxy', 'scheme', 'ip', 'verdict', 'reasons', 'src', 'sl_vpn', 'sl_rproxy', 'sl_dc',
                'i2l_anon', 'i2l_fraud', 'i2l_seen', 'mm_ct', 'mm_asn', 'mm_asnorg', 'mm_org', 'secs']

$('#dl-csv').addEventListener('click', () => download('all.csv',
  [FIELDS.join(','), ...all().map(r => FIELDS.map(f => csvCell(r[f])).join(','))].join('\n'), 'text/csv'))

$('#dl-good').addEventListener('click', () => download('good.txt', passRows().map(r => r.proxy).join('\n')))

$('#dl-cable').addEventListener('click', () => download('good_cable_dsl.txt',
  passRows().filter(r => r.mm_ct === 'Cable/DSL').map(r => r.proxy).join('\n')))

$('#dl-cell').addEventListener('click', () => download('good_cellular.txt',
  passRows().filter(r => r.mm_ct === 'Cellular').map(r => r.proxy).join('\n')))

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