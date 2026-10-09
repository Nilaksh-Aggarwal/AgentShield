import { QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/app/providers/queryClient'
import { agentActionExamples } from '../model'
import { AgentSecurityPage } from './AgentSecurityPage'

interface SentRequest {
  url: string
  method: string
  body: Record<string, unknown>
}

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

function envelope(data: unknown) {
  return { data, meta: { correlationId: 'corr-agent-ui', timestamp: '2026-10-07T09:00:00Z' } }
}

/** Answers each authorization request with `decide(body)` (and the approval list with nothing); returns the requests sent, in order. */
function serve(decide: (body: Record<string, unknown>, index: number) => Response | Promise<Response>): SentRequest[] {
  const sent: SentRequest[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string, init?: RequestInit) => {
      // The approval panel reads the held calls on load: no approval is waiting in these tests.
      if (input.startsWith('/api/v1/agent/approvals')) {
        return Promise.resolve(json(200, envelope({ items: [] })))
      }

      const body = JSON.parse(typeof init?.body === 'string' ? init.body : '{}') as Record<string, unknown>
      sent.push({ url: input, method: init?.method ?? 'GET', body })
      return Promise.resolve(decide(body, sent.length - 1))
    }),
  )
  return sent
}

const decided = (decision: string, riskLevel: string, reason: string, index = 0) =>
  json(200, envelope({ securityEventId: `01a1148c-0000-7000-8000-00000000000${index}`, decision, riskLevel, reason }))

function renderPage() {
  render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter>
        <AgentSecurityPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function rows() {
  return within(screen.getByRole('list', { name: 'Example agent actions' })).getAllByRole('listitem').filter((row) => row.getAttribute('aria-hidden') !== 'true')
}

const run = () => fireEvent.click(screen.getByRole('button', { name: 'Run the examples' }))

describe('AgentSecurityPage', () => {
  it('is labelled as a preview with example data, and sends nothing until asked', () => {
    const sent = serve(() => decided('Allow', 'Low', 'Permitted'))
    renderPage()

    expect(screen.getByRole('heading', { level: 1, name: 'Agent authorization preview' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: /Example data, not production telemetry/ })).toBeTruthy()
    expect(document.body.textContent).toContain('which only decides: nothing is executed there')
    expect(rows()).toHaveLength(agentActionExamples.length)
    expect(rows().every((row) => row.textContent.includes('Not run yet'))).toBe(true)
    expect(sent).toHaveLength(0)
  })

  it('sends each example as it is, in order, with no field beyond the contract', async () => {
    const sent = serve(() => decided('Block', 'Critical', 'UnknownTool'))
    renderPage()

    run()

    await waitFor(() => expect(sent).toHaveLength(agentActionExamples.length))
    expect(sent.every((request) => new URL(request.url, 'http://localhost').pathname === '/api/v1/agent/actions/authorize' && request.method === 'POST')).toBe(true)
    expect(sent.map((request) => request.body)).toEqual(agentActionExamples.map((example) => example.request))
    for (const request of sent) {
      expect(Object.keys(request.body).every((key) => ['agentId', 'tool', 'action', 'capability', 'inputDecision'].includes(key))).toBe(true)
    }
  })

  it('shows the decision, risk and reason exactly as the API returned them', async () => {
    const answers = [
      ['Allow', 'Low', 'Permitted'],
      ['Review', 'High', 'HumanApprovalRequired'],
      ['Block', 'Critical', 'CriticalActionDenied'],
    ] as const
    serve((_, index) => {
      const [decision, risk, reason] = answers[index % answers.length] ?? answers[0]
      return decided(decision, risk, reason, index)
    })
    renderPage()

    run()

    await waitFor(() => expect(rows()[0]?.textContent).toContain('Allow'))
    const [first, second, third] = rows()
    expect(first?.textContent).toContain('Low risk')
    expect(first?.textContent).toContain('Permitted')
    expect(second?.textContent).toContain('Review')
    expect(second?.textContent).toContain('High risk')
    expect(second?.textContent).toContain('Needs approval')
    expect(third?.textContent).toContain('Block')
    expect(third?.textContent).toContain('Critical risk')
    expect(third?.textContent).toContain('Critical action')
    expect(screen.getByRole('status').textContent).toBe('Decided 9 example actions: 3 allowed, 3 for review, 3 blocked.')
    expect(screen.getByRole('link', { name: 'Open Activity' }).getAttribute('href')).toBe('/activity')
  })

  it('never predicts a decision: an Allow for an unknown tool is shown as the API sent it', async () => {
    // The console has no policy of its own; it shows what the boundary decided, even when that looks surprising.
    serve(() => decided('Allow', 'Low', 'Permitted'))
    renderPage()

    run()

    await waitFor(() => expect(rows().every((row) => row.textContent.includes('Allow'))).toBe(true))
    const unknownTool = rows().find((row) => row.textContent.includes('shell.exec'))
    expect(unknownTool?.textContent).toContain('Allow')
  })

  it('never shows an unknown decision as runnable, and echoes neither it nor an unknown reason', async () => {
    serve(() => json(200, envelope({ securityEventId: 'x', decision: 'Approved', riskLevel: 'Low', reason: 'Policy.AllowEverything' })))
    renderPage()

    run()

    await waitFor(() => expect(rows()[0]?.textContent).toContain('Unknown'))
    const text = document.body.textContent
    expect(text).not.toContain('Approved')
    expect(text).not.toContain('Policy.AllowEverything')
    expect(rows()[0]?.textContent).toContain('Not recognised')
    expect(rows()[0]?.textContent).toContain('Do not run: decision not recognised')
  })

  it('shows only documented fields: rule IDs, arguments and provider text in a tampered response are never rendered', async () => {
    serve(() =>
      json(
        200,
        envelope({
          securityEventId: '01a1148c-0000-7000-8000-000000000009',
          decision: 'Block',
          riskLevel: 'High',
          reason: 'CapabilityNotGranted',
          ruleId: 'AG-001 zq7',
          arguments: { to: 'attacker@example.com zq7' },
          grantedCapabilities: ['payment:execute zq7'],
          providerError: 'zq7 provider',
        }),
      ),
    )
    renderPage()

    run()

    await waitFor(() => expect(rows()[0]?.textContent).toContain('Capability not granted'))
    expect(document.body.textContent).not.toMatch(/zq7|attacker@example\.com|AG-001/)
  })

  it.each([
    [401, 'Authentication required'],
    [403, 'You don’t have permission to request agent authorizations'],
    [429, 'Temporarily rate limited'],
    [500, 'No decision was made'],
  ])('explains a %i, shows no decision and stops at the first failure', async (status, title) => {
    const sent = serve(() => json(status, { title: 'Server title zq7', detail: 'NullReferenceException zq7', status }, { 'Content-Type': 'application/problem+json' }))
    renderPage()

    run()

    expect(await screen.findByRole('heading', { name: title })).toBeTruthy()
    expect(sent).toHaveLength(1)
    expect(rows().every((row) => row.textContent.includes('Not run yet'))).toBe(true)
    expect(document.body.textContent).not.toContain('zq7')
  })

  it('explains an unreachable API', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('Failed to fetch zq7-network'))))
    renderPage()

    run()

    expect(await screen.findByRole('heading', { name: 'Can’t reach the AgentShield API' })).toBeTruthy()
    expect(document.body.textContent).not.toContain('zq7')
  })

  it('states what exists and what does not, claiming enforcement only for the one reference tool', () => {
    serve(() => decided('Allow', 'Low', 'Permitted'))
    renderPage()

    const text = document.body.textContent
    expect(text).toContain('Enforcement for real tools: the gateway runs one built-in reference tool, so other tool calls are still up to the application')
    expect(text).toContain('other tools are decided, not enforced')
    expect(text).not.toMatch(/fully protect|guarantee|prevents every|every tool is enforced/i)
  })

  it('explains the flow from proposal to execution as a static explanation, without a live region of its own', () => {
    const sent = serve(() => decided('Allow', 'Low', 'Permitted'))
    renderPage()

    const flow = screen.getByRole('region', { name: 'From proposal to execution' })
    expect(within(flow).getAllByRole('listitem').map((stage) => stage.firstElementChild?.textContent.replace(/^\d\. /, ''))).toEqual([
      'Agent',
      'Action',
      'Capability',
      'Risk',
      'Policy',
      'Gateway',
      'Execute or stop',
    ])
    expect(flow.textContent).toContain('How it works')
    expect(flow.textContent).toContain('only the gateway can run a tool: its one reference tool, and only on Allow')
    expect(flow.textContent).toContain('Other tools are decided, not run')
    expect(within(flow).getByRole('link', { name: /Try it in the Attack Lab/ }).getAttribute('href')).toBe('/attack-lab?scenario=T-01')
    expect(flow.querySelector('[role="status"], [aria-live]')).toBeNull()
    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(sent).toHaveLength(0)
  })
})
