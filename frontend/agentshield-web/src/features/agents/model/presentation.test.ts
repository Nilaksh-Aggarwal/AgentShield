import { describe, expect, it } from 'vitest'
import { ApiError } from '@/services/api'
import { presentActionDecision, presentAgentActionReason, presentAgentSecurityError } from './presentation'

describe('presentActionDecision', () => {
  it('says what each decision lets the caller do; only Allow may run', () => {
    expect(presentActionDecision('Allow')).toMatchObject({ label: 'Allow', action: 'May run', tone: 'success', known: true })
    expect(presentActionDecision('Review')).toMatchObject({ label: 'Review', action: 'Needs a person’s approval', tone: 'warning', known: true })
    expect(presentActionDecision('Block')).toMatchObject({ label: 'Block', action: 'Must not run', tone: 'danger', known: true })
  })

  it.each(['Quarantine', 'allow', '', 'constructor', 'toString', '__proto__', 42, null, undefined])(
    'never presents an unknown decision (%s) as runnable, and does not echo it',
    (decision) => {
      const presentation = presentActionDecision(decision)

      expect(presentation).toEqual({ label: 'Unknown', action: 'Do not run: decision not recognised', tone: 'warning', known: false })
    },
  )
})

describe('presentAgentActionReason', () => {
  it.each([
    ['Permitted', 'Permitted'],
    ['HumanApprovalRequired', 'Needs approval'],
    ['InputHeldForReview', 'Input under review'],
    ['UnknownAgent', 'Unknown agent'],
    ['UnknownTool', 'Unknown tool'],
    ['UnknownAction', 'Unknown action'],
    ['CapabilityMismatch', 'Wrong capability'],
    ['CapabilityNotGranted', 'Capability not granted'],
    ['CriticalActionDenied', 'Critical action'],
    ['InputBlocked', 'Input blocked'],
    ['CallerNotBoundToAgent', 'Client not bound'],
  ])('explains %s in plain words', (reason, label) => {
    const presentation = presentAgentActionReason(reason)

    expect(presentation.label).toBe(label)
    expect(presentation.explanation.length).toBeGreaterThan(20)
    expect(presentation.explanation).not.toContain(reason)
  })

  it.each(['Policy.BlockHighRisk', 'IO-001', 'constructor', 'hasOwnProperty', '', null])('does not echo an unknown reason (%s)', (reason) => {
    expect(presentAgentActionReason(reason)).toEqual({ label: 'Not recognised', explanation: 'AgentShield gave a reason this console does not recognise.' })
  })
})

describe('presentAgentSecurityError', () => {
  it.each([
    [401, 'Authentication required'],
    [403, 'You don’t have permission to request agent authorizations'],
    [422, 'An example was not accepted'],
    [400, 'An example was not accepted'],
    [500, 'No decision was made'],
    [503, 'No decision was made'],
    [418, 'The request could not be processed'],
  ])('explains HTTP %i without server text', (status, title) => {
    const presentation = presentAgentSecurityError(new ApiError({ kind: 'http', status, correlationId: 'corr-agent-ui', problem: { title: 'Server title zq7', detail: 'NullReferenceException zq7 password=hunter2' } }))

    expect(presentation.title).toBe(title)
    expect(presentation.reference).toBe('corr-agent-ui')
    expect(JSON.stringify(presentation)).not.toContain('zq7')
  })

  it('states the wait for a rate limit when the API gave one', () => {
    expect(presentAgentSecurityError(new ApiError({ kind: 'http', status: 429, retryAfterSeconds: 1 })).description).toContain('Try again in 1 second.')
    expect(presentAgentSecurityError(new ApiError({ kind: 'http', status: 429, retryAfterSeconds: 30 })).description).toContain('Try again in 30 seconds.')
    expect(presentAgentSecurityError(new ApiError({ kind: 'http', status: 429 })).description).toContain('Wait a moment')
  })

  it('explains network failures, timeouts and unknown errors', () => {
    expect(presentAgentSecurityError(new ApiError({ kind: 'network' })).title).toBe('Can’t reach the AgentShield API')
    expect(presentAgentSecurityError(new ApiError({ kind: 'timeout' })).title).toBe('The preview took too long')
    expect(presentAgentSecurityError(new ApiError({ kind: 'invalid-response' })).title).toBe('Unexpected response from the API')
    expect(presentAgentSecurityError(new Error('zq7 boom')).title).toBe('The preview couldn’t run')
  })
})
