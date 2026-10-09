import { afterEach, describe, expect, it, vi } from 'vitest'
import { isApiError } from '@/services/api'
import { findScenario, type AttackScenario } from '../model/scenarios'
import { execution } from '../testFixtures'
import { decideApprovalRun, runScenario, type ApprovalRun } from './runScenario'

interface Sent {
  url: string
  method: string
  body: string
  headers: Headers
}

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

const envelope = (data: unknown, correlationId = 'corr-run') => ({ data, meta: { correlationId, timestamp: '2026-10-07T09:00:00Z' } })

function serve(answer: (index: number) => Response | Promise<Response>): Sent[] {
  const sent: Sent[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      sent.push({ url, method: init?.method ?? 'GET', body: typeof init?.body === 'string' ? init.body : '', headers: new Headers(init?.headers) })
      return Promise.resolve(answer(sent.length - 1))
    }),
  )
  return sent
}

function scenario(id: string): AttackScenario {
  const found = findScenario(id)
  if (!found) {
    throw new Error(`no scenario ${id}`)
  }

  return found
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('runScenario', () => {
  it('sends an input scenario to the firewall as exactly { input }', async () => {
    const sent = serve(() => json(200, envelope({ decision: 'Block' })))
    const input = scenario('I-05')

    const run = await runScenario(input)

    expect(sent).toHaveLength(1)
    expect(sent[0]?.method).toBe('POST')
    expect(sent[0]?.url).toBe('/api/v1/firewall/analyze')
    expect(JSON.parse(sent[0]?.body ?? '')).toEqual({ input: input.kind === 'input' ? input.input : '' })
    expect(run).toMatchObject({ kind: 'input', scenarioId: 'I-05', result: { correlationId: 'corr-run' } })
  })

  it('sends a tool scenario to the gateway unchanged, with no scenario ID, intent, agent or API key in the body', async () => {
    const sent = serve(() => json(200, envelope(execution())))
    const tool = scenario('T-02')

    const run = await runScenario(tool)

    expect(sent).toHaveLength(1)
    expect(sent[0]?.url).toBe('/api/v1/agent/tools/execute')
    expect(JSON.parse(sent[0]?.body ?? '')).toEqual(tool.kind === 'tool' ? tool.request : {})
    expect(sent[0]?.body).not.toMatch(/T-0|intent|agentId|decision|X-API-Key|agentshield-development/i)
    // The browser never holds the key: the Vite proxy adds it server-side.
    expect(sent[0]?.headers.has('X-API-Key')).toBe(false)
    expect(sent[0]?.headers.get('Content-Type')).toBe('application/json')
    expect(run.kind).toBe('tool')
  })

  it('replays by presenting the first execution ID, and reports the API’s 400 as a rejection before any decision', async () => {
    const sent = serve((index) =>
      index === 0
        ? json(200, envelope(execution({ executionId: 'exec-1' })))
        : json(400, { errorCode: 'Request.Malformed', correlationId: 'corr-replay', title: 'zq7 server title' }, { 'Content-Type': 'application/problem+json' }),
    )
    const replay = scenario('T-05')

    const run = await runScenario(replay)

    expect(sent).toHaveLength(2)
    const request = replay.kind === 'replay' ? replay.request : undefined
    expect(JSON.parse(sent[0]?.body ?? '')).toEqual(request)
    expect(JSON.parse(sent[1]?.body ?? '')).toEqual({ ...request, executionId: 'exec-1' })
    expect(run).toEqual({
      kind: 'replay',
      scenarioId: 'T-05',
      first: expect.objectContaining({ execution: expect.objectContaining({ executionId: 'exec-1' }) as unknown }) as unknown,
      second: { status: 'rejected', httpStatus: 400, contractRejection: true, correlationId: 'corr-replay' },
    })
  })

  it('does not call a 400 with another error code a contract rejection', async () => {
    serve((index) => (index === 0 ? json(200, envelope(execution())) : json(400, { errorCode: 'Zq7.Other' })))

    const run = await runScenario(scenario('T-05'))

    expect(run.kind === 'replay' && run.second).toEqual({ status: 'rejected', httpStatus: 400, contractRejection: false, correlationId: expect.any(String) as unknown })
  })

  it('reports an accepted second request as accepted, never as rejected', async () => {
    serve(() => json(200, envelope(execution())))

    const run = await runScenario(scenario('T-05'))

    expect(run.kind === 'replay' && run.second.status).toBe('accepted')
  })

  it('keeps the first result when the second request fails for another reason', async () => {
    serve((index) => (index === 0 ? json(200, envelope(execution())) : json(429, { errorCode: 'RateLimit.Exceeded' }, { 'Retry-After': '7' })))

    const run = await runScenario(scenario('T-05'))

    if (run.kind !== 'replay' || run.second.status !== 'failed') {
      throw new Error('expected a failed second request')
    }

    expect(run.first.execution.executed).toBe(true)
    expect(isApiError(run.second.error) && run.second.error.retryAfterSeconds).toBe(7)
  })

  it('fails the run, without a second request, when the first request fails', async () => {
    const sent = serve(() => json(503, { errorCode: 'Server.Unavailable' }))

    await expect(runScenario(scenario('T-05'))).rejects.toMatchObject({ kind: 'http', status: 503 })
    expect(sent).toHaveLength(1)
  })
})

describe('runScenario / decideApprovalRun: the approval scenario', () => {
  const approvalId = '0192a0f5-0000-4000-8000-0000000000a4'
  const inputEventId = '0192a0f5-0000-7000-8000-0000000000e4'

  function approvalScenario() {
    const found = scenario('T-04')
    if (found.kind !== 'approval') {
      throw new Error('T-04 is not the approval scenario')
    }

    return found
  }

  async function hold(): Promise<ApprovalRun> {
    serve((index) =>
      index === 0
        ? json(200, envelope({ securityEventId: inputEventId, decision: 'Review' }))
        : json(200, envelope(execution({ decision: 'Review', outcome: 'HeldForReview', executed: false, executionId: null, result: null, approvalId }))),
    )
    const run = await runScenario(approvalScenario())
    if (run.kind !== 'approval') {
      throw new Error('expected an approval run')
    }

    vi.unstubAllGlobals()
    return run
  }

  it('analyses the input, then sends the call referencing that analysis in the same, fresh trace', async () => {
    const sent = serve((index) => (index === 0 ? json(200, envelope({ securityEventId: inputEventId, decision: 'Review' })) : json(200, envelope(execution({ approvalId })))))
    const t04 = approvalScenario()

    const run = await runScenario(t04)

    expect(sent.map((request) => request.url)).toEqual(['/api/v1/firewall/analyze', '/api/v1/agent/tools/execute'])
    expect(JSON.parse(sent[0]?.body ?? '')).toEqual({ input: t04.input })
    expect(JSON.parse(sent[1]?.body ?? '')).toEqual({ ...t04.request, inputEventId })
    const trace = sent[0]?.headers.get('X-Correlation-ID')
    expect(trace).toMatch(/^lab-[0-9a-f-]{36}$/)
    expect(sent[1]?.headers.get('X-Correlation-ID')).toBe(trace)
    expect(sent.some((request) => request.headers.has('X-API-Key'))).toBe(false)
    expect(run).toMatchObject({ kind: 'approval', scenarioId: 'T-04' })
    expect(run.kind === 'approval' && run.decision).toBeUndefined()
  })

  it.each([
    [true, '/approve', 'Approved'],
    [false, '/deny', 'Denied'],
  ] as const)('approve=%s posts no body to %s, then presents the approval with the same call', async (approve, path, status) => {
    const run = await hold()
    const sent = serve((index) => (index === 0 ? json(200, envelope({ approvalId, status })) : json(200, envelope(execution({ approvalId })))))

    const decided = await decideApprovalRun(approvalScenario(), run, approve)

    expect(sent).toHaveLength(2)
    expect(sent[0]?.url).toBe(`/api/v1/agent/approvals/${approvalId}${path}`)
    expect(sent[0]?.method).toBe('POST')
    expect(sent[0]?.body).toBe('')
    expect(JSON.parse(sent[1]?.body ?? '')).toEqual({ ...approvalScenario().request, approvalId })
    expect(decided.decision).toEqual({ action: approve ? 'approve' : 'deny', answer: status, correlationId: undefined })
    expect(decided.final?.execution.approvalId).toBe(approvalId)
    expect(decided.analysis).toBe(run.analysis)
    expect(decided.held).toBe(run.held)
  })

  it.each([
    ['Approval.Expired', 'Expired'],
    ['Approval.AlreadyDecided', 'AlreadyDecided'],
    ['Approval.NotFound', 'NotFound'],
  ])('reports a %s refusal as %s, and still lets the gateway answer the presented call', async (errorCode, answer) => {
    const run = await hold()
    const sent = serve((index) =>
      index === 0
        ? json(errorCode === 'Approval.NotFound' ? 404 : 409, { errorCode, correlationId: 'corr-refused', title: 'zq7' }, { 'Content-Type': 'application/problem+json' })
        : json(200, envelope(execution({ decision: 'Block', outcome: 'ApprovalRejected', executed: false, executionId: null, result: null, approvalId }))),
    )

    const decided = await decideApprovalRun(approvalScenario(), run, true)

    expect(sent).toHaveLength(2)
    expect(decided.decision).toEqual({ action: 'approve', answer, correlationId: 'corr-refused' })
    expect(decided.final?.execution.outcome).toBe('ApprovalRejected')
  })

  it('calls a status it does not know Unrecognised, and never echoes it', async () => {
    const run = await hold()
    serve((index) => (index === 0 ? json(200, envelope({ approvalId, status: 'zq7Approved' })) : json(200, envelope(execution({ approvalId })))))

    const decided = await decideApprovalRun(approvalScenario(), run, true)

    expect(decided.decision?.answer).toBe('Unrecognised')
    expect(JSON.stringify(decided.decision)).not.toContain('zq7')
  })

  it.each([
    [403, 'Auth.Forbidden'],
    [409, 'Zq7.Other'],
    [500, 'Server.Unexpected'],
  ])('raises a %i (%s) without presenting the call', async (status, errorCode) => {
    const run = await hold()
    const sent = serve(() => json(status, { errorCode }, { 'Content-Type': 'application/problem+json' }))

    await expect(decideApprovalRun(approvalScenario(), run, true)).rejects.toMatchObject({ kind: 'http', status })
    expect(sent).toHaveLength(1)
  })

  it('sends nothing when the gateway created no approval', async () => {
    const run = await hold()
    const sent = serve(() => json(200, envelope({})))

    for (const missing of [null, '', 7]) {
      const unheld = { ...run, held: { ...run.held, execution: { ...run.held.execution, approvalId: missing as string | null } } }
      await expect(decideApprovalRun(approvalScenario(), unheld, true)).rejects.toThrow('The gateway created no approval for this call.')
    }

    expect(sent).toHaveLength(0)
  })
})
