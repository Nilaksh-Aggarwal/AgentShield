import { describe, expect, it } from 'vitest'
import { ApiError } from '@/services/api'
import { presentAnalysisError } from './errors'

const serverText = 'Npgsql.PostgresException: password=hunter2 at Host=db.internal'

function http(status: number, retryAfterSeconds?: number) {
  return new ApiError({
    kind: 'http',
    status,
    retryAfterSeconds,
    correlationId: 'corr-123',
    problem: { title: serverText, detail: serverText, errorCode: 'Server.Unexpected' },
  })
}

describe('presentAnalysisError', () => {
  it.each([
    [400, 'The request could not be read'],
    [401, 'Authentication required'],
    [403, 'You don’t have permission to analyze inputs'],
    [422, 'Input validation failed'],
    [429, 'Analysis temporarily rate limited'],
    [500, 'AgentShield couldn’t complete the analysis'],
    [502, 'AgentShield couldn’t complete the analysis'],
    [418, 'The request could not be processed'],
  ])('maps HTTP %i to a plain-language title, with the reference for support', (status, title) => {
    const presentation = presentAnalysisError(http(status))

    expect(presentation.title).toBe(title)
    expect(presentation.reference).toBe('corr-123')
  })

  it.each([
    ['network', 'Can’t reach the AgentShield API'],
    ['timeout', 'The analysis took too long'],
    ['aborted', 'The analysis was cancelled'],
    ['invalid-response', 'Unexpected response from the API'],
  ] as const)('maps a %s failure', (kind, title) => {
    expect(presentAnalysisError(new ApiError({ kind, correlationId: 'corr-9' }))).toMatchObject({ title, reference: 'corr-9' })
  })

  it('presents anything that is not an ApiError as an unexpected failure, without its message', () => {
    const presentation = presentAnalysisError(new Error(serverText))

    expect(presentation.title).toBe('AgentShield couldn’t complete the analysis')
    expect(JSON.stringify(presentation)).not.toContain('hunter2')
  })

  it.each([400, 401, 403, 429, 500, 502, 418])('says that no decision was made for HTTP %i', (status) => {
    expect(presentAnalysisError(http(status)).description).toMatch(/No decision was made/)
  })

  it.each([400, 401, 403, 422, 429, 500, 418])('never shows server-provided text for HTTP %i', (status) => {
    const shown = JSON.stringify(presentAnalysisError(http(status, 5)))

    expect(shown).not.toContain('hunter2')
    expect(shown).not.toContain('Npgsql')
    expect(shown).not.toContain('Server.Unexpected')
  })

  it('states the wait only when the API sent Retry-After, in singular or plural', () => {
    expect(presentAnalysisError(http(429, 30))).toMatchObject({ retryAfterSeconds: 30, description: expect.stringContaining('Try again in 30 seconds.') as unknown })
    expect(presentAnalysisError(http(429, 1)).description).toContain('Try again in 1 second.')
    expect(presentAnalysisError(http(429)).description).toContain('Wait a moment')
    expect(presentAnalysisError(http(429)).retryAfterSeconds).toBeUndefined()
  })
})
