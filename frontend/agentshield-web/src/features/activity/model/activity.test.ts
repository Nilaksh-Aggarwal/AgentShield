import { describe, expect, it } from 'vitest'
import { ApiError } from '@/services/api'
import type { ActivityFinding } from '../api/listActivity'
import { decisionFilters, parseOccurredAt, presentActivityError, presentAiStatus, summariseFindings } from './activity'

const injection: ActivityFinding = { code: 'InstructionOverride.IgnorePrevious', category: 'InstructionOverride', severity: 'High' }
const prompt: ActivityFinding = { code: 'SecretExtraction.SystemPromptDisclosure', category: 'SecretExtraction', severity: 'High' }
const aiIncomplete: ActivityFinding = { code: 'InconclusiveAnalysis.AiAnalysisIncomplete', category: 'InconclusiveAnalysis', severity: 'Medium' }

describe('presentAiStatus', () => {
  it.each([
    ['Disabled', 'Not enabled', 'neutral'],
    ['Completed', 'Completed', 'info'],
    ['NotNeeded', 'Not needed', 'neutral'],
    ['Incomplete', 'Incomplete', 'warning'],
  ])('presents %s as "%s"', (status, label, tone) => {
    expect(presentAiStatus(status)).toEqual({ label, tone })
  })

  // A value outside the contract may be a failure reason the history deliberately hides: it is never echoed.
  it.each(['CapacityExceeded', 'TimedOut', 'CircuitOpen', 'RateLimited', 'constructor', '__proto__', '', undefined, 3])(
    'presents %j as not reported, never by its value',
    (status) => {
      expect(presentAiStatus(status)).toEqual({ label: 'Not reported', tone: 'neutral' })
    },
  )
})

describe('summariseFindings', () => {
  it('reports no finding for a clean input', () => {
    expect(summariseFindings([])).toEqual({ primary: undefined, more: 0 })
  })

  it('leads with the most severe finding (the API order) and counts the others', () => {
    expect(summariseFindings([injection, prompt])).toEqual({ primary: 'Instruction override detected', more: 1 })
  })

  it('names the AI safeguard in plain words', () => {
    expect(summariseFindings([aiIncomplete])).toEqual({ primary: 'AI analysis could not be completed', more: 0 })
  })

  it('presents an unknown code and category generically, without echoing them', () => {
    const summary = summariseFindings([{ code: 'Zq7.Unknown', category: 'Zq7Category', severity: 'High' } as unknown as ActivityFinding])

    expect(summary.primary).toBe('Security finding')
    expect(JSON.stringify(summary)).not.toContain('Zq7')
  })
})

describe('parseOccurredAt', () => {
  it('reads an ISO 8601 timestamp', () => {
    expect(parseOccurredAt('2026-10-01T10:42:31Z')?.toISOString()).toBe('2026-10-01T10:42:31.000Z')
  })

  it.each(['not a date', '', undefined, 42, null])('rejects %j', (value) => {
    expect(parseOccurredAt(value)).toBeUndefined()
  })
})

describe('decisionFilters', () => {
  it('offers all decisions and each decision once, in policy order', () => {
    expect(decisionFilters.map((option) => option.value)).toEqual(['all', 'Allow', 'Review', 'Block'])
  })
})

describe('presentActivityError', () => {
  const http = (status: number, extra: Partial<{ detail: string; retryAfterSeconds: number }> = {}) =>
    new ApiError({
      kind: 'http',
      status,
      correlationId: 'corr-err',
      retryAfterSeconds: extra.retryAfterSeconds,
      problem: { title: 'Server title', detail: extra.detail ?? 'NullReferenceException at Store.Query password=hunter2' },
    })

  it.each([
    [401, 'Authentication required'],
    [403, 'You don’t have permission to view activity'],
    [422, 'The activity request was not accepted'],
    [500, 'Activity couldn’t be loaded'],
    [503, 'Activity couldn’t be loaded'],
  ])('presents %i as "%s" with the reference, never the server text', (status, title) => {
    const presentation = presentActivityError(http(status))

    expect(presentation.title).toBe(title)
    expect(presentation.reference).toBe('corr-err')
    expect(JSON.stringify(presentation)).not.toMatch(/NullReference|hunter2|Server title/)
  })

  it('states the wait of a 429 only when the API sent one', () => {
    expect(presentActivityError(http(429, { retryAfterSeconds: 30 })).description).toContain('Try again in 30 seconds.')
    expect(presentActivityError(http(429)).description).not.toMatch(/\d/)
  })

  it.each([
    ['network', 'Can’t reach the AgentShield API'],
    ['timeout', 'Loading activity took too long'],
    ['invalid-response', 'Unexpected response from the API'],
  ] as const)('presents a %s failure', (kind, title) => {
    expect(presentActivityError(new ApiError({ kind })).title).toBe(title)
  })

  it('presents anything else generically', () => {
    expect(presentActivityError(new Error('Secret detail'))).toEqual({ title: 'Activity couldn’t be loaded', description: 'Something unexpected went wrong. Try again.' })
  })
})
