import { QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/app/providers/queryClient'
import { toolGatewayExamples } from '../model'
import { ToolGatewayPreview } from './ToolGatewayPreview'

interface SentRequest {
  url: string
  method: string
  body: Record<string, unknown>
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function envelope(data: unknown) {
  return { data, meta: { correlationId: 'corr-gateway-ui', timestamp: '2026-10-07T09:00:00Z' } }
}

/** Answers each gateway request with `answer(body, index)`; returns the requests sent, in order. */
function serve(answer: (body: Record<string, unknown>, index: number) => Response): SentRequest[] {
  const sent: SentRequest[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string, init?: RequestInit) => {
      const body = JSON.parse(typeof init?.body === 'string' ? init.body : '{}') as Record<string, unknown>
      sent.push({ url: input, method: init?.method ?? 'GET', body })
      return Promise.resolve(answer(body, sent.length - 1))
    }),
  )
  return sent
}

function execution(overrides: Record<string, unknown> = {}) {
  return {
    securityEventId: '01a1148c-0000-7000-8000-000000000001',
    decision: 'Allow',
    executed: true,
    outcome: 'Executed',
    authorizationReason: 'Permitted',
    riskLevel: 'Low',
    executionId: '01a1148c-0000-7000-8000-0000000000e1',
    result: { found: true, text: 'Dependency injection: from the dataset.' },
    ...overrides,
  }
}

const blocked = (outcome: string, reason: string) =>
  execution({ decision: 'Block', executed: false, outcome, authorizationReason: reason, executionId: null, result: null })

function renderPreview() {
  render(
    <QueryClientProvider client={createQueryClient()}>
      <ToolGatewayPreview />
    </QueryClientProvider>,
  )
}

function rows() {
  return within(screen.getByRole('list', { name: 'Example tool calls' })).getAllByRole('listitem').filter((row) => row.getAttribute('aria-hidden') !== 'true')
}

const run = () => fireEvent.click(screen.getByRole('button', { name: 'Run the gateway examples' }))

describe('ToolGatewayPreview', () => {
  it('explains the gateway, lists the examples, and sends nothing until asked', () => {
    const sent = serve(() => json(200, envelope(execution())))
    renderPreview()

    expect(screen.getByRole('heading', { name: 'Tool gateway: enforced execution' })).toBeTruthy()
    expect(document.body.textContent).toContain('only on Allow')
    expect(document.body.textContent).toContain('The agent never holds anything that runs a tool')
    expect(rows()).toHaveLength(toolGatewayExamples.length)
    expect(rows().every((row) => row.textContent.includes('Not run yet'))).toBe(true)
    expect(sent).toHaveLength(0)
  })

  it('sends each example as it is, in order, naming no agent and asserting no authority', async () => {
    const sent = serve(() => json(200, envelope(blocked('Denied', 'UnknownTool'))))
    renderPreview()

    run()

    await waitFor(() => expect(sent).toHaveLength(toolGatewayExamples.length))
    expect(sent.every((request) => new URL(request.url, 'http://localhost').pathname === '/api/v1/agent/tools/execute' && request.method === 'POST')).toBe(true)
    expect(sent.map((request) => request.body)).toEqual(toolGatewayExamples.map((example) => example.request))
    for (const request of sent) {
      expect(Object.keys(request.body).every((key) => ['tool', 'action', 'capability', 'arguments', 'inputDecision'].includes(key))).toBe(true)
    }
  })

  it('shows what the gateway did exactly as returned, and a result only where the tool ran', async () => {
    const answers = [
      execution(),
      execution({ result: { found: false, text: null } }),
      blocked('ArgumentsRejected', 'Permitted'),
      blocked('ArgumentsRejected', 'Permitted'),
      execution({ decision: 'Review', executed: false, outcome: 'HeldForReview', authorizationReason: 'HumanApprovalRequired', riskLevel: 'High', executionId: null, result: null }),
      blocked('Denied', 'CapabilityNotGranted'),
      blocked('ToolUnavailable', 'Permitted'),
      blocked('Denied', 'InputBlocked'),
    ]
    serve((_, index) => json(200, envelope(answers[index])))
    renderPreview()

    run()

    await waitFor(() => expect(rows()[7]?.textContent).toContain('Input blocked'))
    const [lookup, missing, smuggled, , review, notGranted, noTool] = rows()
    expect(lookup?.textContent).toContain('The tool ran')
    expect(lookup?.textContent).toContain('Dependency injection: from the dataset.')
    expect(missing?.textContent).toContain('The tool ran')
    expect(missing?.textContent).toContain('The dataset has nothing on this topic.')
    expect(smuggled?.textContent).toContain('The tool did not run')
    expect(smuggled?.textContent).toContain('Arguments rejected')
    expect(review?.textContent).toContain('Review')
    expect(review?.textContent).toContain('Held for review')
    expect(notGranted?.textContent).toContain('Capability not granted')
    expect(noTool?.textContent).toContain('No tool to run')
    expect(rows().filter((row) => row.textContent.includes('The tool ran'))).toHaveLength(2)
    expect(document.querySelector('[aria-live="polite"]')?.textContent).toBe('Sent 8 example tool calls: the tool ran for 2, and for 6 it did not.')
  })

  it('never shows a result, or a tool that ran, for a response that does not say so in every field', async () => {
    const tampered = [
      execution({ decision: 'Block', outcome: 'Denied', executed: false, result: { found: true, text: 'zq7 leaked result' } }),
      execution({ decision: 'Review', result: { found: true, text: 'zq7 leaked result' } }),
      execution({ executed: false, result: { found: true, text: 'zq7 leaked result' } }),
      execution({ outcome: 'ExecutedAnyway', result: { found: true, text: 'zq7 leaked result' } }),
      execution({ decision: 'Allowed', result: { found: true, text: 'zq7 leaked result' } }),
      execution({ outcome: 'constructor' }),
      execution({ authorizationReason: 'Policy.Zq7Rule', arguments: { query: 'zq7 echo' }, ruleId: 'AG-001' }),
      execution({ result: { found: true, text: 'Fine text', secret: 'zq7 secret' } }),
    ]
    serve((_, index) => json(200, envelope(tampered[index])))
    renderPreview()

    run()

    await waitFor(() => expect(rows()[7]?.textContent).toContain('Fine text'))
    const text = screen.getByRole('list', { name: 'Example tool calls' }).textContent
    expect(text).not.toContain('zq7')
    expect(text).not.toContain('ExecutedAnyway')
    expect(text).not.toContain('AG-001')
    expect(rows().slice(0, 6).every((row) => row.textContent.includes('The tool did not run'))).toBe(true)
    expect(rows()[3]?.textContent).toContain('Not recognised')
    expect(rows()[4]?.textContent).toContain('Unknown')
  })

  it.each([
    [401, 'Authentication required'],
    [403, 'You don’t have permission to execute tools'],
    [429, 'Temporarily rate limited'],
    [500, 'No result was returned'],
  ])('shows a %i in plain language, without server text, and no outcome', async (status, title) => {
    serve(() => json(status, { title: 'Server title zq7', detail: 'NullReferenceException zq7', errorCode: 'Server.Unexpected', correlationId: 'corr-err' }))
    renderPreview()

    run()

    expect((await screen.findByRole('alert')).textContent).toContain(title)
    expect(document.body.textContent).not.toContain('zq7')
    expect(rows().every((row) => row.textContent.includes('Not run yet'))).toBe(true)
  })

  it('shows an unreachable API without inventing an outcome', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('Failed to fetch zq7'))))
    renderPreview()

    run()

    expect((await screen.findByRole('alert')).textContent).toContain('Can’t reach the AgentShield API')
    expect(document.body.textContent).not.toContain('zq7')
  })
})
