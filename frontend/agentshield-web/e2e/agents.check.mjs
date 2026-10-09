// Agent security (Milestones 10 and 11) browser checks over the Chrome DevTools Protocol, no packages: the agent
// authorization preview and the tool gateway preview against the real API (Development demo agents; the Development key is
// research-agent's gateway identity), their failure states, and agent actions and tool calls on the Activity page.
// Started by e2e/run.mjs after the Overview suite; directly: node e2e/agents.check.mjs <outDir> <cdpPort>
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


const base = 'http://localhost:5174'
const previewList = 'ol[aria-label="Example agent actions"]'
const gatewayList = 'ol[aria-label="Example tool calls"]'
const eventsList = 'ol[aria-label="Security events, newest first"]'

// What the real boundary decides for each example with the committed Development agents (appsettings.Development.json).
const expected = [
  ['Read data it is allowed to read', 'Allow', 'Permitted', 'Low risk'],
  ['Draft an email for approval', 'Allow', 'Permitted', 'Medium risk'],
  ['Send an email outside the organisation', 'Review', 'Needs approval', 'High risk'],
  ['Use a tool it holds no capability for', 'Block', 'Capability not granted', 'High risk'],
  ['Write with a read capability', 'Block', 'Wrong capability', 'Medium risk'],
  ['Grant itself a role', 'Block', 'Capability not granted', 'Critical risk'],
  ['Execute a payment it holds the capability for', 'Block', 'Critical action', 'Critical risk'],
  ['Call a tool AgentShield does not know', 'Block', 'Unknown tool', 'Critical risk'],
  ['Safe read after a blocked input', 'Block', 'Input blocked', 'Low risk'],
]

// What the real tool gateway does for each example as research-agent: [title, decision, outcome label, ran, detail].
const gatewayExpected = [
  ['Look up a topic it may read', 'Allow', 'Tool ran', true, 'Dependency injection:'],
  ['Look up a topic the dataset does not have', 'Allow', 'Tool ran', true, 'The dataset has nothing on this topic.'],
  ['Smuggle an extra argument into the call', 'Block', 'Arguments rejected', false, ''],
  ['Send an empty query', 'Block', 'Arguments rejected', false, ''],
  ['Open a web page (high risk)', 'Review', 'Held for review', false, ''],
  ['Send an email it holds no capability for', 'Block', 'Blocked', false, 'Capability not granted'],
  ['Read data: allowed, but no tool here runs it', 'Block', 'No tool to run', false, ''],
  ['Look up a topic after a blocked input', 'Block', 'Blocked', false, 'Input blocked'],
]
// Text the dataset would return for the queries of the examples that must not run (least privilege, rate limiting).
const datasetText = /Dependency injection:|Least privilege:|Rate limiting:/
const gatewayRows = () => evaluate(`[...document.querySelectorAll('${gatewayList} > li:not([aria-hidden=true])')].map((li) => ({ text: li.innerText.replace(/\\s+/g, ' ').trim(), decision: (li.querySelector('span.rounded-full')?.textContent ?? '').split(':')[0].trim() }))`)
async function runGateway() {
  await evaluate(`[...document.querySelectorAll('main button')].find((b) => /Run the gateway examples/.test(b.textContent)).click()`)
  for (let i = 0; i < 60; i++) {
    await sleep(250)
    const status = await evaluate(`document.querySelector('main [aria-live=polite]')?.textContent ?? ''`)
    if (/^Sent/.test(status) || (await evaluate(`!!document.querySelector('#gateway-error-heading')`))) return status
  }
  return ''
}

const previewRows = () => evaluate(`[...document.querySelectorAll('${previewList} > li:not([aria-hidden=true])')].map((li) => ({ text: li.innerText.replace(/\\s+/g, ' ').trim(), decision: (li.querySelector('span.rounded-full')?.textContent ?? '').split(':')[0].trim() }))`)
async function runPreview() {
  await evaluate(`[...document.querySelectorAll('main button')].find((b) => /Run the examples/.test(b.textContent)).click()`)
  for (let i = 0; i < 60; i++) {
    await sleep(250)
    const status = await evaluate(`document.querySelector('main [role=status]')?.textContent ?? ''`)
    if (/^Decided/.test(status) || (await evaluate(`!!document.querySelector('#agents-error-heading')`))) return status
  }
  return ''
}

for (const scheme of ['light', 'dark']) {
  for (const w of [375, 768, 1280]) {
    await setup(w, scheme)
    const tag = `${w}-${scheme}`

    await go(`${base}/agents`)
    const info = await pageChecks(`agents ${tag}`, 'Agent security · AgentShield')
    expect(`agents ${tag}: h1`, info.h1[0] === 'Agent authorization preview', info.h1[0])
    expect(`agents ${tag}: active nav`, JSON.stringify(info.current) === '["Agents"]', JSON.stringify(info.current))
    expect(`agents ${tag}: labelled as example data, not telemetry`, /Example data, not production telemetry/.test(info.text) && /Preview/.test(info.text))
    expect(`agents ${tag}: says the authorization preview executes nothing, and enforcement covers one reference tool only`, /which only decides: nothing is executed there/.test(info.text) && /Enforcement for real tools: the gateway runs one built-in reference tool/.test(info.text))
    expect(`agents ${tag}: no gateway outcome before its examples run`, (await gatewayRows()).every((row) => /Not run yet/.test(row.text) && row.decision === '') && (await gatewayRows()).length === 8)
    expect(`agents ${tag}: no decision before the examples run`, (await previewRows()).every((row) => /Not run yet/.test(row.text) && row.decision === '') && (await previewRows()).length === 9)
    // Read from the real store: no suite before this one holds a call for approval (the gateway example held for review is
    // a tool no executor runs, so it gets no approval).
    for (let i = 0; i < 20 && /Loading the held calls/.test(await evaluate(`document.querySelector('section[aria-labelledby=approvals-heading]')?.innerText ?? ''`)); i++) await sleep(250)
    expect(`agents ${tag}: the approval panel says nothing is waiting, and runs nothing`, /Human approval: held tool calls/.test(info.text) && /No tool call is waiting for a person/.test(await evaluate(`document.querySelector('section[aria-labelledby=approvals-heading]')?.innerText ?? ''`)) && /Nothing here runs a tool\./.test(info.text))
    await contrastScan(`agents ${tag}`)
    await touchTargets(`agents ${tag}`)
    await shot(`agents-${tag}`)

    const status = await runPreview()
    expect(`agents ${tag}: the real boundary decided every example`, status === 'Decided 9 example actions: 2 allowed, 1 for review, 6 blocked.', status)
    const rows = await previewRows()
    expected.forEach(([title, decision, reason, risk], index) => {
      const row = rows[index] ?? { text: '', decision: '' }
      expect(`agents ${tag}: "${title}" → ${decision} (${reason}, ${risk})`, row.text.includes(title) && row.decision === decision && row.text.includes(reason) && row.text.includes(risk), JSON.stringify(row))
    })
    const gatewayStatus = await runGateway()
    expect(`agents ${tag}: the real gateway handled every example`, gatewayStatus === 'Sent 8 example tool calls: the tool ran for 2, and for 6 it did not.', gatewayStatus)
    const handled = await gatewayRows()
    gatewayExpected.forEach(([title, decision, outcome, ran, detail], index) => {
      const row = handled[index] ?? { text: '', decision: '' }
      const ok = row.text.includes(title) && row.decision === decision && row.text.includes(outcome)
        && row.text.includes(ran ? 'The tool ran' : 'The tool did not run') && (!detail || row.text.includes(detail))
      expect(`agents ${tag}: gateway "${title}" → ${decision}, ${outcome}`, ok, JSON.stringify(row))
    })
    expect(`agents ${tag}: no dataset text in a row whose tool did not run`, handled.filter((row) => /The tool did not run/.test(row.text)).every((row) => !datasetText.test(row.text)), handled.map((row) => row.text.slice(0, 60)).join(' | '))
    const after = await pageChecks(`agents decided ${tag}`, 'Agent security · AgentShield')
    expect(`agents decided ${tag}: no rule IDs, policy names, raw reason or outcome codes, grants or signatures`, !/Policy\.|AG-\d|CapabilityNotGranted|HumanApprovalRequired|CallerNotBound|ArgumentsRejected|ExecutionAuthorizationRejected|ToolUnavailable|UnexpectedArgument|signature|ExecutionGrant/.test(after.text))
    await contrastScan(`agents decided ${tag}`)
    await touchTargets(`agents decided ${tag}`)
    await shot(`agents-decided-${tag}`)
  }
}
expect('agents pages, widths and schemes: no console errors or warnings', consoleErrors.length === 0, consoleErrors.join(' | '))

// ---- Activity lists the agent actions, metadata only ----------------------------------------------------------------
consoleErrors = []
await setup(1280, 'light'); await go(`${base}/activity`)
for (let i = 0; i < 40 && !(await evaluate(`!!document.querySelector('${eventsList}')`)); i++) await sleep(250)
// Text content, not innerText: each row's kind badge is followed by a spoken ": " that innerText would lay out on its own line.
const activity = await evaluate(`document.querySelector('main').textContent`)
expect('activity: agent actions are listed as agent → tool.action with their reason', /Agent action: research-agent → data\.read · Input blocked/.test(activity) && /Agent action: support-agent → unknown tool, unknown action · Unknown tool/.test(activity), (activity.match(/Agent action:.{0,60}/g) ?? []).slice(0, 4).join(' | '))
expect('activity: agent actions have no AI analysis and no score', /Not applicable/.test(activity))
expect('activity: tool calls are listed as agent → tool.action with what the gateway did', /Tool call: research-agent → knowledge\.lookup · Tool ran/.test(activity) && /Tool call: research-agent → knowledge\.lookup · Arguments rejected/.test(activity) && /Tool call: research-agent → browser\.navigate · Held for review/.test(activity), (activity.match(/Tool call:.{0,60}/g) ?? []).slice(0, 4).join(' | '))
expect('activity: no tool arguments or results', !/passwd|"query"|example\.com|Dependency injection: a class/.test(activity))
expect('activity: no tool arguments, raw reason codes or made-up names', !/"to":|attacker@|CapabilityMismatch|CriticalActionDenied|shell:exec/.test(activity))
await evaluate(`[...document.querySelectorAll('${eventsList} details')].find((d) => /Agent action/.test(d.innerText)).querySelector('summary').click()`); await sleep(200)
const opened = await evaluate(`[...document.querySelectorAll('${eventsList} details')].find((d) => d.open)?.querySelector('dl')?.innerText ?? ''`)
expect('activity: an agent action opens to its trace IDs, claimed capability and reason', /Security event ID/.test(opened) && /Capability claimed/.test(opened) && /Reason/.test(opened), opened)
await evaluate(`[...document.querySelectorAll('${eventsList} details')].forEach((d) => { d.open = false })`)
await evaluate(`[...document.querySelectorAll('${eventsList} details')].find((d) => /Tool call: .* · Tool ran/.test(d.textContent)).querySelector('summary').click()`); await sleep(200)
const openedCall = await evaluate(`[...document.querySelectorAll('${eventsList} details')].find((d) => d.open)?.querySelector('dl')?.innerText ?? ''`)
expect('activity: a tool call opens to whether the tool ran and its execution ID', /Ran once/.test(openedCall) && /Execution ID/.test(openedCall) && /What happened/.test(openedCall), openedCall)
await contrastScan('activity with agent actions 1280-light')
await shot('activity-agent-actions-1280-light')
expect('activity run: no console errors', consoleErrors.length === 0, consoleErrors.join(' | '))

// ---- Keyboard ---------------------------------------------------------------------------------------------------------
consoleErrors = []
await setup(1280, 'light'); await go(`${base}/agents`)
for (let i = 0; i < 8; i++) await tab()
expect('keyboard: after skip link, brand and the five nav links comes "Run the examples"', /Run the examples/.test(await active() ?? ''), await active())
expect('keyboard: focus ring on "Run the examples"', /solid 2px/.test(await outlineOfActive()), await outlineOfActive())
await enter()
for (let i = 0; i < 60 && !/^Decided/.test(await evaluate(`document.querySelector('main [role=status]')?.textContent ?? ''`)); i++) await sleep(250)
expect('keyboard: Enter runs the examples', /^Decided 9/.test(await evaluate(`document.querySelector('main [role=status]')?.textContent ?? ''`)))
expect('keyboard run: no console errors', consoleErrors.length === 0, consoleErrors.join(' | '))

// ---- Failures: wrong key, no permission, API unreachable ----------------------------------------------------------------
consoleErrors = []
for (const [port, title] of [[5175, 'Authentication required'], [5177, 'You don’t have permission to request agent authorizations'], [5178, 'No decision was made']]) {
  await setup(375, 'dark'); await go(`http://localhost:${port}/agents`)
  await runPreview()
  const heading = await evaluate(`document.querySelector('#agents-error-heading')?.textContent ?? ''`)
  expect(`agents ${port}: "${title}"`, heading === title, heading)
  const failed = await pageChecks(`agents error ${port}`, 'Agent security · AgentShield')
  expect(`agents ${port}: no decisions and no server text`, (await previewRows()).every((row) => /Not run yet/.test(row.text) && row.decision === '') && !/errorCode|Exception|Problem|traceId|Server title/i.test(failed.text))
  const approvalTitle = { 5175: 'Authentication required', 5177: 'You don’t have permission to approve tool calls', 5178: 'AgentShield couldn’t complete the approval request' }[port]
  // A 502 is transient: the list query retries it twice (about 3 s) before it explains the failure.
  const panelAlertText = () => evaluate(`document.querySelector('section[aria-labelledby=approvals-heading] [role=alert] h3')?.textContent ?? ''`)
  for (let i = 0; i < 60 && !(await panelAlertText()); i++) await sleep(250)
  const panelAlert = await panelAlertText()
  expect(`agents ${port}: the approval panel explains "${approvalTitle}" and lists nothing`, panelAlert === approvalTitle && !(await evaluate(`!!document.querySelector('ul[aria-label="Held tool calls, newest first"]')`)), panelAlert)
  await contrastScan(`agents error ${port}`)
  await shot(`agents-error-${port}-375-dark`)
}
for (const [port, title] of [[5175, 'Authentication required'], [5177, 'You don’t have permission to execute tools'], [5178, 'No result was returned']]) {
  await setup(1280, 'light'); await go(`http://localhost:${port}/agents`)
  await runGateway()
  const heading = await evaluate(`document.querySelector('#gateway-error-heading')?.textContent ?? ''`)
  expect(`gateway ${port}: "${title}"`, heading === title, heading)
  const failedText = await evaluate(`document.querySelector('main').innerText`)
  expect(`gateway ${port}: no outcome and no server text`, (await gatewayRows()).every((row) => /Not run yet/.test(row.text) && row.decision === '') && !/errorCode|Exception|Problem|traceId|Server title/i.test(failedText))
  await contrastScan(`gateway error ${port}`)
  await shot(`gateway-error-${port}-1280-light`)
}
const unexpected = consoleErrors.filter((c) => !/status of (401|403|502)/.test(c))
expect('agents failure runs: only the expected 401/403/502 responses in the console', unexpected.length === 0, unexpected.join(' | '))

// ---- Reduced motion -----------------------------------------------------------------------------------------------------
await setup(1280, 'light', true); await go(`${base}/agents`)
const anim = await evaluate(`[...document.querySelectorAll('*')].filter((el) => { const s = getComputedStyle(el); return s.animationName !== 'none' || (s.transitionDuration !== '0s' && /transform|all/.test(s.transitionProperty)) }).length`)
expect('reduced motion: nothing animates or moves on Agent security', anim === 0, anim)

writeFileSync(join(outDir, 'report.json'), JSON.stringify({ fail, results }, null, 2))
console.log(`checks: ${results.length}, failed: ${fail.length}`)
for (const f of fail) console.log('FAIL', f)
ws.close(); process.exit(fail.length === 0 ? 0 : 1)
