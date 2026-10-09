import { describe, expect, it } from 'vitest'
import { ApiError } from '@/services/api'
import { presentApprovalError, presentApprovalStatus } from './approvals'

const http = (status: number, errorCode?: string) =>
  new ApiError({ kind: 'http', status, correlationId: `corr-${status}`, problem: { title: 'Server title zq7', detail: 'zq7 detail', errorCode } })

describe('presentApprovalStatus', () => {
  it('offers a choice only for a pending approval, and says the tool did not run when it was denied or expired', () => {
    const presented = Object.fromEntries(['Pending', 'Approved', 'Used', 'Denied', 'Expired'].map((status) => [status, presentApprovalStatus(status)]))

    expect(Object.entries(presented).filter(([, presentation]) => presentation.pending).map(([status]) => status)).toEqual(['Pending'])
    expect(presented.Pending?.label).toBe('Pending approval')
    expect(presented.Approved?.explanation).toContain('exactly this call once')
    expect(presented.Used?.label).toBe('Approved and used')
    expect(presented.Denied?.explanation).toMatch(/^Tool not executed/)
    expect(presented.Expired?.explanation).toMatch(/^Tool not executed/)
  })

  it('never echoes, approves or offers a choice for a status it does not know, inherited names included', () => {
    for (const status of ['pending', 'APPROVED', 'Approve', 'zq7', '', 'constructor', '__proto__', 'toString', null, 1, { status: 'Pending' }]) {
      const presentation = presentApprovalStatus(status)
      expect(presentation).toMatchObject({ label: 'Not recognised', tone: 'warning', pending: false })
      expect(presentation.explanation).toContain('treat the call as not approved')
    }
  })
})

describe('presentApprovalError', () => {
  it('explains each refusal from its status and stable code, never from the server text', () => {
    expect(presentApprovalError(http(403, 'Auth.Forbidden'))).toEqual({
      title: 'You don’t have permission to approve tool calls',
      description: 'This client is signed in but does not hold the approval permission. Nothing was decided.',
      reference: 'corr-403',
    })
    expect(presentApprovalError(http(404, 'Approval.NotFound')).title).toBe('No such approval')
    expect(presentApprovalError(http(409, 'Approval.Expired')).title).toBe('The approval expired')
    expect(presentApprovalError(http(409, 'Approval.AlreadyDecided')).title).toBe('Already decided')
    expect(presentApprovalError(http(409, 'Zq7.Other')).title).toBe('Already decided')
    expect(presentApprovalError(http(502))).toEqual({
      title: 'AgentShield couldn’t complete the approval request',
      description: 'Nothing was approved or denied. If it keeps happening, quote the reference below.',
      reference: 'corr-502',
    })
    expect(presentApprovalError(http(500)).title).toBe('AgentShield couldn’t complete the approval request')
    for (const status of [403, 404, 409, 500, 502]) {
      expect(JSON.stringify(presentApprovalError(http(status, 'Approval.Expired')))).not.toContain('zq7')
    }
  })

  it('falls back to the agent security explanations for everything else', () => {
    expect(presentApprovalError(http(401)).title).toBe('Authentication required')
    expect(presentApprovalError(http(429)).title).toBe('Temporarily rate limited')
    expect(presentApprovalError(new ApiError({ kind: 'network' })).title).toBe('Can’t reach the AgentShield API')
    expect(presentApprovalError(new Error('zq7')).title).toBe('The preview couldn’t run')
  })
})
