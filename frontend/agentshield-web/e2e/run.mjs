// Runs the committed browser checks (e2e/*.check.mjs) against the real API: two API instances, five preview servers and
// headless Chrome, all on fixed local ports, then stops everything. No packages beyond Node, .NET and Chrome or Edge.
// AI-assisted analysis is forced off and the Gemini key blanked for both API instances, so nothing is sent to a provider
// whatever the developer's User Secrets contain. See e2e/README.md.
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const e2eDir = dirname(fileURLToPath(import.meta.url))
const webDir = resolve(e2eDir, '..')
const repoDir = resolve(webDir, '..', '..')
const apiDll = process.env.AGENTSHIELD_API_DLL ?? join(repoDir, 'src', 'AgentShield.Api', 'bin', 'Debug', 'net10.0', 'AgentShield.Api.dll')
const viteBin = join(webDir, 'node_modules', 'vite', 'bin', 'vite.js')
const cdpPort = 9333

// Ports the checks address. 5112/5113 avoid the API's usual 5102, 5199 must stay unused ("API unreachable").
const api = { normal: 5112, limited: 5113, unreachable: 5199 }
const noPermissionKey = 'agentshield-local-test-key-without-permissions'
const previews = [
  { port: 5174, target: api.normal },
  { port: 5175, target: api.normal, devKey: 'this-key-is-deliberately-wrong-for-a-401-test' },
  { port: 5176, target: api.limited },
  { port: 5177, target: api.limited, devKey: noPermissionKey },
  { port: 5178, target: api.unreachable },
]
const suites = [
  { name: 'analyze', script: 'analyze.check.mjs' },
  { name: 'overview', script: 'overview.check.mjs' },
  // After the Overview suite, so the Activity checks there see only the Analyze suite's analyses.
  { name: 'agents', script: 'agents.check.mjs' },
  // Last: its Activity checks find its own runs by correlation ID, whatever the suites before it recorded.
  { name: 'attack-lab', script: 'attack-lab.check.mjs' },
]

const children = []
const temporary = []
const log = (line) => console.log(`[e2e] ${line}`)
const sleep = (ms) => new Promise((done) => setTimeout(done, ms))

async function main() {
  if (!existsSync(join(webDir, 'dist', 'index.html'))) {
    throw new Error('No production build: run "npm run build" first.')
  }

  if (!existsSync(apiDll)) {
    throw new Error(`No API build at ${apiDll}: run "dotnet build AgentShield.slnx" first (or set AGENTSHIELD_API_DLL).`)
  }

  const chrome = findChrome()
  const busy = []
  for (const port of [api.normal, api.limited, api.unreachable, cdpPort, ...previews.map((preview) => preview.port)]) {
    if (await isListening(port)) {
      busy.push(port)
    }
  }

  if (busy.length > 0) {
    throw new Error(`Ports already in use: ${busy.join(', ')}. Stop whatever listens there, then run again.`)
  }

  startApi(api.normal, {})
  startApi(api.limited, {
    RateLimiting__Firewall__PermitLimit: '3',
    // Approvals expire after 3 seconds here, so the Attack Lab checks can decide one too late.
    ToolApprovals__LifetimeSeconds: '3',
    Authentication__Clients__noperm__KeyHashes__0: createHash('sha256').update(noPermissionKey).digest('hex'),
  })
  await Promise.all([waitFor(`http://localhost:${api.normal}/health/live`), waitFor(`http://localhost:${api.limited}/health/live`)])
  log(`API instances ready on ${api.normal} and ${api.limited} (AI off)`)

  for (const preview of previews) {
    start('node', [viteBin, 'preview', '--port', String(preview.port), '--strictPort'], {
      cwd: webDir,
      env: {
        VITE_API_PROXY_TARGET: `http://localhost:${preview.target}`,
        ...(preview.devKey ? { AGENTSHIELD_DEV_API_KEY: preview.devKey } : {}),
      },
    })
  }

  await Promise.all(previews.map((preview) => waitFor(`http://localhost:${preview.port}/`)))
  log(`preview servers ready on ${previews.map((preview) => preview.port).join(', ')}`)

  const profile = mkdtempSync(join(tmpdir(), 'agentshield-e2e-chrome-'))
  temporary.push(profile)
  start(chrome, [
    '--headless=new',
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    'about:blank',
  ])
  await waitFor(`http://127.0.0.1:${cdpPort}/json/version`)
  log(`headless browser ready (${chrome})`)

  const resultsDir = join(e2eDir, '.results', new Date().toISOString().replaceAll(':', '-').slice(0, 19))
  let failed = 0
  for (const suite of suites) {
    const outDir = join(resultsDir, suite.name)
    mkdirSync(outDir, { recursive: true })
    log(`running ${suite.name} checks`)
    const run = spawnSync(process.execPath, [join(e2eDir, suite.script), outDir, String(cdpPort)], { stdio: 'inherit' })
    if (run.status !== 0) {
      failed++
      log(`${suite.name}: FAILED (exit ${run.status ?? run.signal})`)
    }
  }

  log(`screenshots and reports: ${resultsDir}`)
  return failed
}

function startApi(port, settings) {
  // Its own working directory: the Development file sink writes logs/ relative to it.
  const workDir = mkdtempSync(join(tmpdir(), `agentshield-e2e-api-${port}-`))
  temporary.push(workDir)
  start('dotnet', [apiDll, '--contentRoot', dirname(apiDll)], {
    cwd: workDir,
    env: {
      ASPNETCORE_ENVIRONMENT: 'Development',
      ASPNETCORE_URLS: `http://localhost:${port}`,
      Ai__Enabled: 'false',
      Ai__Gemini__ApiKey: '',
      ...settings,
    },
  })
}

function start(command, args, { cwd = webDir, env = {} } = {}) {
  const child = spawn(command, args, {
    cwd,
    env: { ...process.env, ...env },
    stdio: 'ignore',
    detached: process.platform !== 'win32',
  })
  child.on('error', (error) => log(`could not start ${command}: ${error.message}`))
  children.push(child)
  return child
}

async function stopAll() {
  const exited = []
  for (const child of children.reverse()) {
    if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) {
      continue
    }

    exited.push(new Promise((done) => child.once('exit', done)))
    if (process.platform === 'win32') {
      spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' })
    } else {
      try {
        process.kill(-child.pid, 'SIGTERM')
      } catch {
        // Already gone.
      }
    }
  }

  // Windows frees a killed process's open files (the API's log file, Chrome's profile) only once it has exited, so the
  // directories go after that (T-05: removing them straight after taskkill failed with EPERM). One that still cannot be
  // removed is reported and left in the temp folder: cleanup must never turn the checks' result into a failure.
  await Promise.race([Promise.all(exited), sleep(15_000)])
  for (const directory of temporary) {
    try {
      rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 })
    } catch (error) {
      log(`warning: could not remove ${directory} (${error.code ?? error.message})`)
    }
  }
}

async function waitFor(url, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url)
      if (response.ok) {
        return
      }
    } catch {
      // Not up yet.
    }

    await sleep(300)
  }

  throw new Error(`Timed out waiting for ${url}`)
}

function isListening(port) {
  const probe = (host) =>
    new Promise((done) => {
      const socket = connect({ host, port })
      socket.setTimeout(500)
      socket.once('connect', () => {
        socket.destroy()
        done(true)
      })
      socket.once('timeout', () => {
        socket.destroy()
        done(false)
      })
      socket.once('error', () => done(false))
    })
  return Promise.all([probe('127.0.0.1'), probe('::1')]).then((results) => results.includes(true))
}

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    ...(process.platform === 'win32'
      ? [
          join(process.env.PROGRAMFILES ?? 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          join(process.env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          join(process.env.LOCALAPPDATA ?? '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          join(process.env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        ]
      : process.platform === 'darwin'
        ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']
        : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge']),
  ].filter(Boolean)
  const found = candidates.find((candidate) => existsSync(candidate))
  if (!found) {
    throw new Error('No Chrome or Edge found: set CHROME_PATH.')
  }

  return found
}

let exitCode = 1
try {
  const failed = await main()
  exitCode = failed === 0 ? 0 : 1
  log(failed === 0 ? 'all browser checks passed' : `${failed} suite(s) failed`)
} catch (error) {
  log(`ERROR: ${error instanceof Error ? error.message : String(error)}`)
} finally {
  await stopAll()
}

process.exit(exitCode)
