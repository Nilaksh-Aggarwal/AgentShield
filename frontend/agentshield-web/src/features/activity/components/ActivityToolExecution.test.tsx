import { QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/app/providers/queryClient'
import { ActivityPage } from './ActivityPage'

const toolItem = {
  securityEventId: '0192a0f5-0000-7000-8000-0000000000a1',
  correlationId: 'corr-tool-1',
  occurredAt: '2026-10-07T10:42:31Z',
  kind: 'ToolExecution',
  decision: 'Allow',
  risk: { level: 'Low', score: null },
  findings: [],
  aiAnalysis: null,
  agentAction: { agentId: 'research-agent', tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', reason: 'Permitted' },
  toolExecution: { outcome: 'Executed', executed: true, executionId: '0192a0f5-0000-7000-8000-0000000000e1' },
}

function pageOf(items: unknown[]) {
  return {
    data: { items, page: 1, pageSize: 25, totalCount: items.length, totalPages: items.length === 0 ? 0 : 1 },
    meta: { correlationId: 'corr-ui-activity', timestamp: '2026-10-07T10:43:00Z' },
  }
}

function serve(items: unknown[]) {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify(pageOf(items)), { status: 200, headers: { 'Content-Type': 'application/json' } }))))
}

function renderPage() {
  const client = createQueryClient()
  client.setDefaultOptions({ queries: { ...client.getDefaultOptions().queries, retry: false } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ActivityPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function rows() {
  const list = await screen.findByRole('list', { name: 'Security events, newest first' })
  return within(list).getAllByRole('listitem')
}

describe('ActivityPage: tool calls through the gateway', () => {
  it('shows a tool call as which agent ran which action and what the gateway did, without a score or AI status', async () => {
    serve([toolItem])
    renderPage()

    const [row] = await rows()
    expect(row?.textContent).toContain('Tool call: research-agent → knowledge.lookup · Tool ran')
    expect(row?.textContent).toContain('Allow')
    expect(row?.textContent).toContain('Low risk')
    expect(row?.textContent).toContain('Not applicable')
    expect(row?.textContent).not.toContain('null')
    expect(row?.textContent).not.toContain('No findings')
  })

  it('opens a tool call to whether the tool ran, what happened, its execution ID and the authorization reason', async () => {
    serve([toolItem])
    renderPage()

    const [row] = await rows()
    fireEvent.click(row!.querySelector('summary')!)

    const details = row!.querySelector('dl')!.textContent
    expect(details).toContain('Ran once')
    expect(details).toContain('ran the tool once')
    expect(details).toContain('0192a0f5-0000-7000-8000-0000000000e1')
    expect(details).toContain('knowledge:read')
    expect(details).toContain('The agent holds the capability this action requires')
  })

  it.each([
    ['ArgumentsRejected', 'Block', 'Arguments rejected'],
    ['HeldForReview', 'Review', 'Held for review'],
    ['ToolUnavailable', 'Block', 'No tool to run'],
    ['ExecutionAuthorizationRejected', 'Block', 'Grant refused'],
  ])('shows a %s call as one that did not run', async (outcome, decision, label) => {
    serve([{ ...toolItem, decision, toolExecution: { outcome, executed: false, executionId: null } }])
    renderPage()

    const [row] = await rows()
    expect(row?.textContent).toContain(`· ${label}`)
    fireEvent.click(row!.querySelector('summary')!)
    const details = row!.querySelector('dl')!.textContent
    expect(details).toContain('Did not run')
    expect(details).not.toContain('Execution ID')
  })

  it('never shows a tool that ran unless the record says so in both fields, and never echoes an unknown outcome', async () => {
    serve([
      { ...toolItem, securityEventId: 'a', toolExecution: { outcome: 'Executed', executed: false, executionId: null } },
      { ...toolItem, securityEventId: 'b', toolExecution: { outcome: 'ZQ7Outcome', executed: true, executionId: null } },
      { ...toolItem, securityEventId: 'c', toolExecution: { outcome: 'constructor', executed: true, executionId: null } },
    ])
    renderPage()

    const items = await rows()
    for (const row of items) {
      fireEvent.click(row.querySelector('summary')!)
      expect(row.querySelector('dl')!.textContent).toContain('Did not run')
    }
    expect(items[1]?.textContent).toContain('Not recognised')
    expect(document.body.textContent).not.toContain('ZQ7Outcome')
  })

  it('renders only documented fields: arguments, results and rejection reasons never reach the page', async () => {
    serve([
      {
        ...toolItem,
        agentAction: { ...toolItem.agentAction, arguments: { query: 'zq7 query' } },
        toolExecution: { ...toolItem.toolExecution, result: 'zq7 result text', argumentViolation: 'UnexpectedArgument', grantRejection: 'AlreadyUsed' },
        arguments: { query: 'zq7 query' },
      },
    ])
    renderPage()

    const [row] = await rows()
    fireEvent.click(row!.querySelector('summary')!)
    expect(document.body.textContent).not.toContain('zq7')
    expect(document.body.textContent).not.toContain('UnexpectedArgument')
    expect(document.body.textContent).not.toContain('AlreadyUsed')
  })
})
