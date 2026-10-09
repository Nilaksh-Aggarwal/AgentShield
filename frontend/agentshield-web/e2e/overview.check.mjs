// Overview, Activity, Not found and shell browser checks (Phase B4) over the Chrome DevTools Protocol, no packages.
// Started by e2e/run.mjs; directly: node e2e/overview.check.mjs <outDir> <cdpPort>
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const [outDir, port] = [process.argv[2], process.argv[3]]
mkdirSync(outDir, { recursive: true })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json()
const ws = new WebSocket(target.webSocketDebuggerUrl)
await new Promise((r) => ws.addEventListener('open', r))
let id = 0
const pending = new Map()
let consoleErrors = []
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data)
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id) }
  if (msg.method === 'Runtime.exceptionThrown') consoleErrors.push(`exception: ${msg.params.exceptionDetails.text}`)
  if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(msg.params.type)) consoleErrors.push(`${msg.params.type}: ${msg.params.args.map((a) => a.value ?? a.description).join(' ')}`)
  if (msg.method === 'Log.entryAdded' && ['error', 'warning'].includes(msg.params.entry.level)) consoleErrors.push(`log: ${msg.params.entry.text} ${msg.params.entry.url ?? ''}`)
})
const send = (method, params = {}) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); ws.send(JSON.stringify({ id: i, method, params })) })
const evaluate = async (expression) => {
  const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (res.result?.exceptionDetails) throw new Error(`${expression.slice(0, 100)} → ${res.result.exceptionDetails.exception?.description ?? res.result.exceptionDetails.text}`)
  return res.result?.result?.value
}
await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable')

const results = []
const fail = []
const expect = (name, ok, detail = '') => { results.push({ name, ok: !!ok, detail }); if (!ok) fail.push(`${name} :: ${String(detail).slice(0, 300)}`) }
let width = 1280
async function setup(w, scheme, reducedMotion = false) {
  width = w
  await send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: w < 600 })
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }, { name: 'prefers-reduced-motion', value: reducedMotion ? 'reduce' : 'no-preference' }] })
}
async function go(url) { await send('Page.navigate', { url }); await sleep(1000) }
async function shot(name) {
  const { result } = await send('Page.getLayoutMetrics')
  await send('Emulation.setDeviceMetricsOverride', { width, height: Math.max(900, Math.ceil(result.cssContentSize.height)), deviceScaleFactor: 1, mobile: width < 600 })
  await sleep(150)
  const s = await send('Page.captureScreenshot', { format: 'png' })
  writeFileSync(join(outDir, `${name}.png`), Buffer.from(s.result.data, 'base64'))
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 })
}
async function key(k, code, keyCode, modifiers = 0) {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, windowsVirtualKeyCode: keyCode, modifiers, ...(k === 'Enter' ? { text: '\r' } : {}) })
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: keyCode, modifiers })
  await sleep(80)
}
const tab = () => key('Tab', 'Tab', 9)
const enter = () => key('Enter', 'Enter', 13)
const active = () => evaluate(`(() => { const a = document.activeElement; return a ? (a.id ? '#' + a.id : '') + '<' + a.tagName.toLowerCase() + '>' + (a.textContent || '').trim().slice(0, 50) : null })()`)
const outlineOfActive = () => evaluate(`(() => { const s = getComputedStyle(document.activeElement); return s.outlineStyle + ' ' + s.outlineWidth })()`)

const pageChecks = async (label, expectedTitle) => {
  const info = await evaluate(`(() => ({
    title: document.title,
    h1: [...document.querySelectorAll('h1')].map((h) => h.textContent),
    landmarks: [document.querySelectorAll('nav[aria-label=Primary]').length, document.querySelectorAll('main#main-content').length, document.querySelectorAll('footer').length],
    overflow: document.documentElement.scrollWidth > window.innerWidth,
    clipped: [...document.querySelectorAll('main *')].filter((el) => { const s = getComputedStyle(el); return el.getBoundingClientRect().width > 1 && el.scrollWidth > el.clientWidth + 1 && (s.overflowX === 'hidden' || s.overflowX === 'clip') && el.textContent.trim() }).map((el) => el.tagName + ':' + el.textContent.trim().slice(0, 30)),
    text: document.body.innerText,
    headingOrder: [...document.querySelectorAll('main h1, main h2, main h3, main h4')].map((h) => Number(h.tagName[1])),
    current: [...document.querySelectorAll('nav [aria-current=page]')].map((a) => a.textContent.trim()),
  }))()`)
  expect(`${label}: title`, info.title === expectedTitle, info.title)
  expect(`${label}: one h1`, info.h1.length === 1, info.h1.join(' | '))
  expect(`${label}: landmarks`, info.landmarks.join() === '1,1,1', info.landmarks)
  expect(`${label}: no horizontal page overflow`, !info.overflow)
  expect(`${label}: no clipped text`, info.clipped.length === 0, info.clipped.join(' | '))
  expect(`${label}: no template/milestone text`, !/milestone|vite|react logo|count is|lorem ipsum/i.test(info.text))
  expect(`${label}: no percentages or invented metrics`, !/\d\s?%|accuracy of|detection rate|\b\d[\d,.]*\s*(customers|users|companies|attacks (blocked|stopped)|requests (analy[sz]ed|protected))/i.test(info.text), (info.text.match(/.{0,30}(\d\s?%|accuracy of|detection rate).{0,20}/i) ?? [''])[0])
  expect(`${label}: no absolute claims`, !/stops every|100\s?% (secure|safe)|all threats|guaranteed? (safe|protection)|unbreakable|bulletproof/i.test(info.text))
  expect(`${label}: no rule IDs, detectors or evidence`, !/\b(IO|RM|SE|OB)-\d{3}\b|OB-(HID|B64|MASK|PCT|HTML)|AI-FAIL|evidence rule/i.test(info.text))
  let skipped = false
  for (let i = 1; i < info.headingOrder.length; i++) if (info.headingOrder[i] - info.headingOrder[i - 1] > 1) skipped = true
  expect(`${label}: heading levels never skip`, !skipped && info.headingOrder[0] === 1, info.headingOrder.join(''))
  return info
}
const contrastScan = (label) => evaluate(`(() => {
  const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1; const ctx = canvas.getContext('2d', { willReadFrequently: true })
  const rgba = (css) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = '#000'; ctx.fillStyle = css; ctx.fillRect(0, 0, 1, 1); const d = ctx.getImageData(0, 0, 1, 1).data; return [d[0], d[1], d[2], d[3] / 255] }
  const over = (top, bottom) => { const a = top[3]; return [top[0] * a + bottom[0] * (1 - a), top[1] * a + bottom[1] * (1 - a), top[2] * a + bottom[2] * (1 - a), 1] }
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4 }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]) }
  const background = (el) => { const layers = []; for (let n = el; n; n = n.parentElement) { const c = rgba(getComputedStyle(n).backgroundColor); if (c[3] > 0) layers.push(c); if (c[3] >= 1) break } let bg = [255, 255, 255, 1]; if (layers.length && layers[layers.length - 1][3] >= 1) bg = layers.pop(); for (let i = layers.length - 1; i >= 0; i--) bg = over(layers[i], bg); return bg }
  const failures = []; let checked = 0; let min = 99
  for (const el of document.querySelectorAll('main *, header *, footer *')) {
    if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue
    const r = el.getBoundingClientRect(); if (r.width < 2 || r.height < 2) continue
    if (el.closest('[disabled],[aria-hidden=true]')) continue
    const s = getComputedStyle(el); if (s.visibility === 'hidden' || Number(s.opacity) === 0) continue
    const bg = background(el); const fg = over(rgba(s.color), bg)
    const L1 = lum(fg), L2 = lum(bg); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05)
    const size = parseFloat(s.fontSize); const bold = Number(s.fontWeight) >= 700; const large = size >= 24 || (bold && size >= 18.66)
    checked++; min = Math.min(min, ratio)
    if (ratio < (large ? 3 : 4.5)) failures.push(el.tagName + ' "' + el.textContent.trim().slice(0, 40) + '" ' + ratio.toFixed(2))
  }
  return { checked, min: Number(min.toFixed(2)), failures }
})()`).then((c) => expect(`${label}: text contrast AA (${c.checked} elements, min ${c.min})`, c.failures.length === 0, c.failures.join(' | ')))
const touchTargets = (label) => evaluate(`(() => {
  const small = []
  for (const el of document.querySelectorAll('main button, main summary, nav a, main a.inline-flex')) { const r = el.getBoundingClientRect(); if (r.width && r.height < 43.5) small.push(el.textContent.trim().slice(0, 30) + ' ' + Math.round(r.height)) }
  return small
})()`).then((small) => expect(`${label}: touch targets >= 44px`, small.length === 0, small.join(' | ')))

// Activity: the texts the Analyze suite submits (examples and typed inputs) must never appear on the Activity page.
const analysedText = /quarterly sales report|New instructions: from now on|Ignore all previous instructions|developer mode|print your system prompt|API keys or passwords|reveal your system prompt|Something else entirely/i
const aiFailureReasons = /\b(CapacityExceeded|TimedOut|CircuitOpen|RateLimited|NetworkFailure|MalformedResponse|InvalidResponse|ContentWithheld|UnclassifiedFailure)\b/
const eventsList = 'ol[aria-label="Security events, newest first"]'
async function waitForActivity() {
  for (let i = 0; i < 40; i++) {
    if (await evaluate(`!!document.querySelector('${eventsList}, #activity-error-heading') || /No activity yet/.test(document.body.innerText)`)) return
    await sleep(250)
  }
}
const activityState = () => evaluate(`(() => {
  const rows = [...document.querySelectorAll('${eventsList} > li:not([aria-hidden=true])')]
  return {
    rows: rows.length,
    decisions: rows.map((li) => li.querySelector('summary span.rounded-full')?.textContent.trim() ?? ''),
    filters: [...document.querySelectorAll('[role=group][aria-label="Show decisions"] button')].map((b) => b.textContent.trim() + ':' + b.getAttribute('aria-pressed')),
    text: document.querySelector('main').innerText,
    charts: document.querySelectorAll('main canvas, main svg:not([aria-hidden=true])').length,
  }
})()`)
const clickButton = (scope, label) => evaluate(`[...document.querySelectorAll('${scope} button')].find((b) => b.textContent.trim() === ${JSON.stringify(label)}).click()`)

const base = 'http://localhost:5174'
for (const scheme of ['light', 'dark']) {
  for (const w of [375, 768, 1280]) {
    await setup(w, scheme)
    const tag = `${w}-${scheme}`

    await go(`${base}/`)
    const ov = await pageChecks(`overview ${tag}`, 'Overview · AgentShield')
    expect(`overview ${tag}: hero h1`, ov.h1[0] === 'Protect AI applications from malicious instructions', ov.h1[0])
    expect(`overview ${tag}: active nav`, JSON.stringify(ov.current) === '["Overview"]', JSON.stringify(ov.current))
    const sections = await evaluate(`[...document.querySelectorAll('main section h2, main h2')].map((h) => h.textContent.trim())`)
    for (const h of ['What AgentShield checks for, and how it decides', 'Why not just keyword filtering?', 'One pipeline for every input', 'The AI is a signal, not the authority', 'Protections built in', 'What AgentShield does not claim', 'See AgentShield in action', 'What this API process has decided']) {
      expect(`overview ${tag}: section "${h}"`, sections.includes(h), sections.join(' | '))
    }
    expect(`overview ${tag}: 9 capabilities`, (await evaluate(`document.querySelectorAll('[aria-labelledby=capabilities-heading] article').length`)) === 9)
    expect(`overview ${tag}: reused pipeline with 9 stages`, (await evaluate(`document.querySelectorAll('#how-it-works [aria-labelledby=pipeline-heading] ol > li').length`)) === 9)
    expect(`overview ${tag}: 8 protections`, (await evaluate(`document.querySelectorAll('[aria-labelledby=by-design-heading] article').length`)) === 8)
    expect(`overview ${tag}: 7 AI situations`, (await evaluate(`document.querySelectorAll('[aria-labelledby=ai-failures-heading] ul > li').length`)) === 7)
    expect(`overview ${tag}: Allow is not a guarantee`, /Allow is not a guarantee/.test(ov.text))
    // The Analyze suite ran first against the same API: the counts are real, read from this process's history.
    for (let i = 0; i < 20 && !(await evaluate(`!!document.querySelector('[aria-labelledby=operations-heading] dl')`)); i++) await sleep(250)
    const operations = await evaluate(`[...document.querySelectorAll('[aria-labelledby=operations-heading] dl > div')].map((d) => d.querySelector('dt').textContent + '=' + d.querySelector('dd').textContent)`)
    expect(`overview ${tag}: security operations shows each count under its label, from the real history`, operations.length === 8 && /^Events held=[1-9]\d*$/.test(operations[0]) && operations.every((o) => /=\d+$/.test(o)), operations.join(' | '))
    expect(`overview ${tag}: security operations is labelled as this process's in-memory history, not a period`, /in memory, in this API process only, at most its last 1,000 events, cleared when it restarts/.test(ov.text) && !/last \d+ days|this (week|month)|trend/i.test(ov.text))
    expect(`overview ${tag}: no hidden characters or payloads`, !/[\u{E0000}-\u{E007F}\u{FE00}-\u{FE0F}]/u.test(ov.text) && !/reveal your system prompt\b/i.test(ov.text))
    const pipelineLayout = await evaluate(`(() => { const lis = [...document.querySelectorAll('#how-it-works ol > li')].map((li) => li.getBoundingClientRect()); return new Set(lis.map((r) => Math.round(r.left))).size })()`)
    expect(`overview ${tag}: pipeline ${w < 768 ? 'vertical' : '3 columns'}`, pipelineLayout === (w < 768 ? 1 : 3), pipelineLayout)
    const colHeaders = await evaluate(`getComputedStyle(document.querySelector('[aria-labelledby=keyword-heading] ul > li')).display`)
    expect(`overview ${tag}: disguise table headers ${w < 768 ? 'hidden' : 'shown'}`, w < 768 ? colHeaders === 'none' : colHeaders === 'grid', colHeaders)
    await contrastScan(`overview ${tag}`)
    await touchTargets(`overview ${tag}`)
    await shot(`overview-${tag}`)

    // The Analyze suite ran first against the same API, so the history holds its analyses (attacks included).
    await go(`${base}/activity`)
    await waitForActivity()
    const ac = await pageChecks(`activity ${tag}`, 'Activity · AgentShield')
    expect(`activity ${tag}: h1`, ac.h1[0] === 'Security activity', ac.h1[0])
    expect(`activity ${tag}: active nav`, JSON.stringify(ac.current) === '["Activity"]')
    const act = await activityState()
    expect(`activity ${tag}: lists the analyses the Analyze checks made, Block included`, act.rows > 0 && act.decisions.includes('Block'), JSON.stringify(act.decisions))
    expect(`activity ${tag}: four decision filters, All pressed`, JSON.stringify(act.filters) === '["All:true","Allowed:false","Review:false","Blocked:false"]', JSON.stringify(act.filters))
    expect(`activity ${tag}: paged`, /Page \d+ of \d+/.test(act.text))
    expect(`activity ${tag}: metadata only, none of the analysed text`, !analysedText.test(act.text), (act.text.match(analysedText) ?? [''])[0])
    expect(`activity ${tag}: no hidden characters`, !/[\u{E0000}-\u{E007F}\u{FE00}-\u{FE0F}]/u.test(act.text))
    expect(`activity ${tag}: no AI failure reason`, !aiFailureReasons.test(act.text), (act.text.match(aiFailureReasons) ?? [''])[0])
    expect(`activity ${tag}: no charts`, act.charts === 0)
    expect(`activity ${tag}: honest about what is kept and for how long`, /never stored or shown/.test(act.text) && /starts empty when the server restarts/.test(act.text))
    await contrastScan(`activity ${tag}`)
    await touchTargets(`activity ${tag}`)
    await shot(`activity-${tag}`)

    await go(`${base}/does-not-exist`)
    await pageChecks(`404 ${tag}`, 'Page not found · AgentShield')
    await contrastScan(`404 ${tag}`)
    if (w === 375) await shot(`notfound-${tag}`)
  }
}
expect('all pages, widths and schemes: no console errors or warnings', consoleErrors.length === 0, consoleErrors.join(' | '))
consoleErrors = []

// ---- Keyboard and anchors ----------------------------------------------------------------------------------------
await setup(1280, 'light'); await go(`${base}/`)
for (let i = 0; i < 8; i++) await tab()
expect('keyboard: after skip link, brand and nav comes "Open the Attack Lab"', /Open the Attack Lab/.test(await active() ?? ''), await active())
expect('keyboard: focus ring on hero action', /solid 2px/.test(await outlineOfActive()), await outlineOfActive())
await tab()
expect('keyboard: then "Analyze an input"', /Analyze an input/.test(await active() ?? ''), await active())
await tab()
expect('keyboard: then "How it works"', /How it works/.test(await active() ?? ''), await active())
await enter(); await sleep(300)
const how = await evaluate(`(() => ({ active: document.activeElement?.id, top: Math.round(document.querySelector('#how-it-works').getBoundingClientRect().top), hash: location.hash }))()`)
expect('"How it works" moves focus to and scrolls to the pipeline section', how.active === 'how-it-works' && how.top >= 0 && how.top < 120 && how.hash === '#how-it-works', JSON.stringify(how))
await tab()
expect('keyboard: next Tab continues after the section', !/Analyze an input|How it works|See the full pipeline/.test(await active() ?? ''), await active())
await go(`${base}/`)
await evaluate(`(() => { const all = [...document.querySelectorAll('a, button, [tabindex]')].filter((e) => e.tabIndex >= 0); const i = all.findIndex((a) => a.textContent.includes('Open Analyzer')); all[i - 1].focus() })()`)
await tab()
expect('keyboard: focus ring on "Open Analyzer"', /solid 2px/.test(await outlineOfActive()), await outlineOfActive())
await enter(); await sleep(600)
expect('"Open Analyzer" opens /analyze and focuses main', (await evaluate('location.pathname')) === '/analyze' && /#main-content/.test(await active() ?? ''), await active())
await go(`${base}/`)
await evaluate(`[...document.querySelectorAll('a')].find((a) => a.textContent.includes('See the full pipeline')).click()`); await sleep(300)
expect('"See the full pipeline" focuses the pipeline section', (await evaluate('document.activeElement?.id')) === 'how-it-works')
expect('keyboard/anchor run: no console errors', consoleErrors.length === 0, consoleErrors.join(' | '))

// ---- Activity: filter, paging, row details, keyboard --------------------------------------------------------------
consoleErrors = []
await setup(1280, 'light'); await go(`${base}/activity`); await waitForActivity()
await clickButton('[role=group][aria-label="Show decisions"]', 'Blocked'); await sleep(800)
const blocked = await activityState()
expect('activity filter: Blocked is pressed and lists only Block events', blocked.filters.includes('Blocked:true') && blocked.rows > 0 && blocked.decisions.every((d) => d === 'Block'), JSON.stringify(blocked.decisions))
await evaluate(`document.querySelector('${eventsList} details summary').click()`); await sleep(200)
const opened = await evaluate(`(() => { const d = document.querySelector('${eventsList} details'); return { open: d.open, ids: d.querySelector('dl').innerText } })()`)
expect('activity row: opens to its security event and correlation IDs', opened.open && /Security event ID/.test(opened.ids) && /Correlation ID/.test(opened.ids) && /[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/.test(opened.ids), opened.ids)
await contrastScan('activity filtered, row open 1280-light')
await shot('activity-filtered-open-1280-light')
// Reached with a real Tab from the control before it, as a keyboard user would (a scripted focus shows no focus ring).
await evaluate(`(() => { const all = [...document.querySelectorAll('a, button, summary, [tabindex]')].filter((e) => e.tabIndex >= 0 && !e.disabled); all[all.indexOf(document.querySelector('${eventsList} details summary')) - 1].focus() })()`)
await tab()
expect('keyboard: Tab reaches the first activity row', await evaluate(`document.activeElement === document.querySelector('${eventsList} details summary')`), await active())
expect('keyboard: focus ring on an activity row', /solid 2px/.test(await outlineOfActive()), await outlineOfActive())
await enter(); await sleep(150)
expect('keyboard: Enter closes the activity row again', (await evaluate(`document.querySelector('${eventsList} details').open`)) === false)
await clickButton('[role=group][aria-label="Show decisions"]', 'All'); await sleep(800)
const firstPage = await activityState()
expect('activity: the Analyze checks filled more than one page', /Page 1 of [2-9]/.test(firstPage.text), (firstPage.text.match(/Page \d+ of \d+/) ?? [''])[0])
await clickButton('nav[aria-label="Activity pages"]', 'Next'); await sleep(800)
const secondPage = await activityState()
expect('activity paging: Next shows page 2', /Page 2 of \d+/.test(secondPage.text) && secondPage.rows > 0, (secondPage.text.match(/Page \d+ of \d+/) ?? [''])[0])
expect('activity run: no console errors', consoleErrors.length === 0, consoleErrors.join(' | '))

// ---- Activity failures: wrong key, no permission, API unreachable ----------------------------------------------------
consoleErrors = []
for (const [port, title] of [[5175, 'Authentication required'], [5177, 'You don’t have permission to view activity'], [5178, 'Activity couldn’t be loaded']]) {
  await setup(375, 'dark'); await go(`http://localhost:${port}/activity`)
  let heading = ''
  for (let i = 0; i < 40 && !heading; i++) { await sleep(250); heading = await evaluate(`document.querySelector('#activity-error-heading')?.textContent ?? ''`) }
  expect(`activity ${port}: "${title}"`, heading === title, heading)
  const info = await pageChecks(`activity error ${port}`, 'Activity · AgentShield')
  expect(`activity ${port}: no events and no server text`, !(await evaluate(`!!document.querySelector('${eventsList}')`)) && !/errorCode|Exception|Problem|traceId|Server title/i.test(info.text))
  await contrastScan(`activity error ${port}`)
  await shot(`activity-error-${port}-375-dark`)
}
const unexpectedActivity = consoleErrors.filter((c) => !/status of (401|403|502)/.test(c))
expect('activity failure runs: only the expected 401/403/502 responses in the console', unexpectedActivity.length === 0, unexpectedActivity.join(' | '))

// ---- Shell with the API unreachable -----------------------------------------------------------------------------
consoleErrors = []
for (const [w, scheme] of [[375, 'light'], [1280, 'dark']]) {
  await setup(w, scheme); await go('http://localhost:5178/')
  let pill = ''
  for (let i = 0; i < 40 && pill !== 'API unavailable'; i++) { await sleep(250); pill = await evaluate(`document.querySelector('header [role=status]')?.textContent`) }
  expect(`API down ${w}-${scheme}: header says API unavailable`, pill === 'API unavailable', pill)
  const info = await pageChecks(`API down overview ${w}-${scheme}`, 'Overview · AgentShield')
  expect(`API down ${w}-${scheme}: page still fully rendered`, /See AgentShield in action/.test(info.text))
  await contrastScan(`API down ${w}-${scheme}`)
  await shot(`api-down-${w}-${scheme}`)
}
const unexpected = consoleErrors.filter((c) => !/status of 502/.test(c))
expect('API-down run: only the expected 502 health requests in the console', unexpected.length === 0, unexpected.join(' | '))

// ---- Reduced motion ---------------------------------------------------------------------------------------------
await setup(1280, 'light', true); await go(`${base}/`)
const anim = await evaluate(`[...document.querySelectorAll('*')].filter((el) => { const s = getComputedStyle(el); return s.animationName !== 'none' || (s.transitionDuration !== '0s' && /transform|all/.test(s.transitionProperty)) }).length`)
expect('reduced motion: nothing animates or moves on the Overview', anim === 0, anim)
await go(`${base}/activity`); await waitForActivity()
const activityAnim = await evaluate(`[...document.querySelectorAll('*')].filter((el) => { const s = getComputedStyle(el); return s.animationName !== 'none' || (s.transitionDuration !== '0s' && /transform|all/.test(s.transitionProperty)) }).length`)
expect('reduced motion: nothing animates or moves on Activity', activityAnim === 0, activityAnim)

writeFileSync(join(outDir, 'report.json'), JSON.stringify({ fail, results }, null, 2))
console.log(`checks: ${results.length}, failed: ${fail.length}`)
for (const f of fail) console.log('FAIL', f)
ws.close(); process.exit(fail.length === 0 ? 0 : 1)
