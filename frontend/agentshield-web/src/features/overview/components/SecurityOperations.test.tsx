import { QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/app/providers/queryClient'
import { SecurityOperations } from './SecurityOperations'

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const summary = {
  totalCount: 14,
  oldestOccurredAt: '2026-10-07T08:00:00Z',
  newestOccurredAt: '2026-10-07T09:30:00Z',
  decisions: { allow: 5, review: 2, block: 7 },
  kinds: { inputAnalysis: 9, agentActionAuthorization: 2, toolExecution: 3 },
  toolsExecuted: 1,
}

function serve(response: () => Response | Promise<Response>) {
  const fetchMock = vi.fn<(url: string) => Promise<Response>>(() => Promise.resolve(response()))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function renderSection() {
  const client = createQueryClient()
  client.setDefaultOptions({ queries: { ...client.getDefaultOptions().queries, retry: false } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SecurityOperations />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** The value shown for a count label, as text. */
function valueOf(label: string): string | null | undefined {
  return screen.getByText(label).nextElementSibling?.textContent
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('SecurityOperations', () => {
  it('reads the summary endpoint and shows each count under its label, with an honest scope', async () => {
    const fetchMock = serve(() => json(200, { data: summary, meta: { correlationId: 'c', timestamp: '2026-10-07T09:31:00Z' } }))
    renderSection()

    expect(await screen.findByText('Events held')).toBeTruthy()
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/activity/summary')
    expect(valueOf('Events held')).toBe('14')
    expect(valueOf('Allowed')).toBe('5')
    expect(valueOf('Held for review')).toBe('2')
    expect(valueOf('Blocked')).toBe('7')
    expect(valueOf('Inputs analysed')).toBe('9')
    expect(valueOf('Agent actions decided')).toBe('2')
    expect(valueOf('Tool calls through the gateway')).toBe('3')
    expect(valueOf('Tools that ran')).toBe('1')

    const section = screen.getByRole('region', { name: 'What this API process has decided' })
    expect(section.textContent).toContain('in memory, in this API process only, at most its last 1,000 events, cleared when it restarts')
    expect(section.textContent).toContain('Attack Lab runs included')
    expect(section.textContent).toContain('Oldest event held:')
    expect(section.textContent).not.toMatch(/last \d+ days|this week|this month|today|trend|%/i)
  })

  it('shows no numbers while loading', () => {
    serve(() => new Promise<Response>(() => undefined))
    renderSection()

    const section = screen.getByRole('region', { name: 'What this API process has decided' })
    expect(within(section).getByText('Loading the counts…')).toBeTruthy()
    expect(section.textContent?.replace('1,000', '')).not.toMatch(/\d/)
  })

  it('invites a first run instead of a wall of zeros when nothing has been decided', async () => {
    serve(() => json(200, { data: { ...summary, totalCount: 0, oldestOccurredAt: null, newestOccurredAt: null, decisions: { allow: 0, review: 0, block: 0 }, kinds: { inputAnalysis: 0, agentActionAuthorization: 0, toolExecution: 0 }, toolsExecuted: 0 }, meta: { correlationId: 'c', timestamp: 't' } }))
    renderSection()

    expect(await screen.findByText('No security events yet')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Open the Attack Lab' }).getAttribute('href')).toBe('/attack-lab')
    expect(screen.queryByText('Events held')).toBeNull()
  })

  it.each([
    [403, 'You don’t have permission to view activity'],
    [401, 'Authentication required'],
    [500, 'Activity couldn’t be loaded'],
  ])('shows a %i as a failure, never as zeros', async (status, title) => {
    serve(() => json(status, { title: 'zq7', errorCode: 'X', correlationId: 'corr-ops' }))
    renderSection()

    expect(await screen.findByText(title)).toBeTruthy()
    const section = screen.getByRole('region', { name: 'What this API process has decided' })
    expect(section.textContent).toContain('The counts couldn’t be loaded, so none are shown.')
    expect(section.textContent).toContain('corr-ops')
    expect(section.textContent).not.toContain('zq7')
    expect(screen.queryByText('Events held')).toBeNull()
  })

  it('shows a count that is not one as not reported, never as a number it made up', async () => {
    serve(() => json(200, { data: { ...summary, decisions: { allow: -1, review: 2.5, block: 'zq7' }, kinds: null, toolsExecuted: Number.MAX_SAFE_INTEGER }, meta: { correlationId: 'c', timestamp: 't' } }))
    renderSection()

    expect(await screen.findByText('Events held')).toBeTruthy()
    for (const label of ['Allowed', 'Held for review', 'Blocked', 'Inputs analysed', 'Agent actions decided', 'Tool calls through the gateway']) {
      expect(valueOf(label)).toBe('Not reported')
    }

    expect(document.body.textContent).not.toContain('zq7')
  })
})
