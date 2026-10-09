import { QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/app/providers/queryClient'
import { ApprovalsPanel } from './ApprovalsPanel'

interface Sent {
  url: string
  method: string
  body: string | undefined
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const envelope = (data: unknown) => ({ data, meta: { correlationId: 'corr-approvals-ui', timestamp: '2026-10-07T09:00:00Z' } })

function approval(overrides: Record<string, unknown> = {}) {
  return {
    approvalId: '0192a0f5-0000-4000-8000-0000000000a1',
    status: 'Pending',
    securityEventId: '0192a0f5-0000-7000-8000-0000000000b1',
    correlationId: 'corr-held',
    agentId: 'support-agent',
    tool: 'knowledge',
    action: 'lookup',
    capability: 'knowledge:read',
    riskLevel: 'High',
    reason: 'HumanApprovalRequired',
    inputDecision: null,
    requestedAt: '2026-10-07T09:00:00Z',
    expiresAt: '2026-10-07T09:10:00Z',
    decidedAt: null,
    ...overrides,
  }
}

/** Answers the list with `list()` and decisions with `decide(url)`; returns every request sent. */
function serve(list: () => Response, decide: (url: string) => Response = () => json(200, envelope(approval({ status: 'Approved' })))): Sent[] {
  const sent: Sent[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      sent.push({ url, method: init?.method ?? 'GET', body: typeof init?.body === 'string' ? init.body : undefined })
      return Promise.resolve((init?.method ?? 'GET') === 'GET' ? list() : decide(url))
    }),
  )
  return sent
}

function renderPanel() {
  const client = createQueryClient()
  client.setDefaultOptions({ queries: { ...client.getDefaultOptions().queries, retry: false } })
  render(
    <QueryClientProvider client={client}>
      <ApprovalsPanel />
    </QueryClientProvider>,
  )
}

const items = () => within(screen.getByRole('list', { name: 'Held tool calls, newest first' })).getAllByRole('listitem')

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ApprovalsPanel', () => {
  it('shows a pending approval with the agent, tool, action, risk and reason, and the two choices', async () => {
    serve(() => json(200, envelope({ items: [approval()] })))
    renderPanel()

    const [item] = await waitFor(items)
    expect(item?.textContent).toContain('Pending approval')
    expect(item?.textContent).toContain('support-agent')
    expect(item?.textContent).toContain('knowledge.lookup')
    expect(item?.textContent).toContain('High risk')
    expect(item?.textContent).toContain('A high-risk action: a person must approve it before it runs.')
    expect(within(item!).getByRole('button', { name: 'Approve' })).toBeTruthy()
    expect(within(item!).getByRole('button', { name: 'Deny' })).toBeTruthy()
    expect(document.body.textContent).toContain('Nothing here runs a tool.')
  })

  it.each([
    ['Approve', '/approve', 'Approved', 'The agent may run exactly this call once'],
    ['Deny', '/deny', 'Denied', 'Tool not executed'],
  ])('%s sends no body, then shows the status the API returns', async (button, path, label, explanation) => {
    let status = 'Pending'
    const sent = serve(
      () => json(200, envelope({ items: [approval({ status })] })),
      (url) => {
        status = url.endsWith('/approve') ? 'Approved' : 'Denied'
        return json(200, envelope(approval({ status })))
      },
    )
    renderPanel()

    fireEvent.click(await screen.findByRole('button', { name: button }))

    await waitFor(() => expect(items()[0]?.textContent).toContain(label))
    expect(items()[0]?.textContent).toContain(explanation)
    const decision = sent.find((request) => request.method === 'POST')!
    expect(decision.url).toBe(`/api/v1/agent/approvals/0192a0f5-0000-4000-8000-0000000000a1${path}`)
    expect(decision.body).toBeUndefined()
    expect(within(items()[0]!).queryByRole('button', { name: 'Approve' })).toBeNull()
    expect(document.querySelector('[aria-live="polite"]')?.textContent).toContain(label)
  })

  it.each([
    ['Expired', 'Expired', 'Tool not executed'],
    ['Used', 'Approved and used', 'can never authorise anything again'],
    ['Denied', 'Denied', 'Tool not executed'],
  ])('shows %s as final: no choices', async (status, label, explanation) => {
    serve(() => json(200, envelope({ items: [approval({ status })] })))
    renderPanel()

    const [item] = await waitFor(items)
    expect(item?.textContent).toContain(label)
    expect(item?.textContent).toContain(explanation)
    expect(within(item!).queryByRole('button')).toBeNull()
  })

  it('never echoes or acts on a status, reason or field it does not know', async () => {
    serve(() =>
      json(200, envelope({ items: [approval({ status: 'zq7Approved', reason: 'zq7Reason', arguments: { query: 'zq7 secret query' }, argumentsDigest: 'zq7digest' })] })),
    )
    renderPanel()

    const [item] = await waitFor(items)
    expect(item?.textContent).toContain('Not recognised')
    expect(within(item!).queryByRole('button')).toBeNull()
    expect(document.body.textContent).not.toContain('zq7')
  })

  it('explains a client without the approval permission, and shows no approvals', async () => {
    serve(() => json(403, { title: 'zq7 forbidden', errorCode: 'Auth.Forbidden', correlationId: 'corr-forbidden' }))
    renderPanel()

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('You don’t have permission to approve tool calls')
    expect(alert.textContent).toContain('corr-forbidden')
    expect(screen.queryByRole('list', { name: 'Held tool calls, newest first' })).toBeNull()
    expect(document.body.textContent).not.toContain('zq7')
  })

  it('explains a decision the API refuses, without its text', async () => {
    serve(
      () => json(200, envelope({ items: [approval()] })),
      () => json(409, { title: 'zq7 conflict', errorCode: 'Approval.Expired', correlationId: 'corr-expired' }),
    )
    renderPanel()

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('The approval expired')
    expect(document.body.textContent).not.toContain('zq7')
  })

  it('says so when nothing is waiting', async () => {
    serve(() => json(200, envelope({ items: [] })))
    renderPanel()

    expect(await screen.findByText(/No tool call is waiting for a person/)).toBeTruthy()
  })
})
