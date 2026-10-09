import { describe, expect, it } from 'vitest'
import { ApiError } from '@/services/api'
import type { ToolExecution } from '../api/executeTool'
import { describeArguments, presentToolGatewayError, presentToolOutcome, resultText, toolRan } from './gateway'
import { toolGatewayExamples } from './gatewayExamples'

const executed: ToolExecution = {
  securityEventId: '01a1148c-0000-7000-8000-000000000001',
  decision: 'Allow',
  executed: true,
  outcome: 'Executed',
  authorizationReason: 'Permitted',
  riskLevel: 'Low',
  executionId: '01a1148c-0000-7000-8000-0000000000e1',
  result: { found: true, text: 'Dependency injection: the composition root chooses.' },
  approvalId: null,
}

describe('presentToolOutcome', () => {
  it('names every outcome the gateway reports, and only an execution as a tool that ran', () => {
    const outcomes = ['Executed', 'HeldForReview', 'Denied', 'ArgumentsRejected', 'ToolUnavailable', 'ExecutionAuthorizationRejected', 'ExecutionFailed', 'InputContextRejected', 'ApprovalRejected']
    const labels = outcomes.map((outcome) => presentToolOutcome(outcome).label)

    expect(labels).toEqual(['Tool ran', 'Held for review', 'Blocked', 'Arguments rejected', 'No tool to run', 'Grant refused', 'Tool failed', 'Input event rejected', 'Approval rejected'])
    expect(presentToolOutcome('Executed').tone).toBe('success')
    expect(outcomes.slice(1).every((outcome) => presentToolOutcome(outcome).tone !== 'success')).toBe(true)
  })

  it('never echoes an outcome it does not know, inherited names included', () => {
    for (const value of ['ExecutedAnyway', 'constructor', '__proto__', 'toString', 42, null, undefined, { label: 'Tool ran' }]) {
      const presentation = presentToolOutcome(value)
      expect(presentation.label).toBe('Not recognised')
      expect(JSON.stringify(presentation)).not.toContain('ExecutedAnyway')
    }
  })
})

describe('toolRan', () => {
  it('needs an Allow, the executed flag and the Executed outcome together', () => {
    expect(toolRan(executed)).toBe(true)
    expect(toolRan({ ...executed, decision: 'Review' })).toBe(false)
    expect(toolRan({ ...executed, decision: 'Block' })).toBe(false)
    expect(toolRan({ ...executed, decision: 'Allowed' as never })).toBe(false)
    expect(toolRan({ ...executed, executed: false })).toBe(false)
    expect(toolRan({ ...executed, executed: 'true' as never })).toBe(false)
    expect(toolRan({ ...executed, outcome: 'ExecutionFailed' })).toBe(false)
    expect(toolRan({ ...executed, outcome: 'Unknown' as never })).toBe(false)
  })
})

describe('resultText', () => {
  it('is the result only for a tool that ran and found something', () => {
    expect(resultText(executed)).toBe('Dependency injection: the composition root chooses.')
    expect(resultText({ ...executed, result: { found: false, text: null } })).toBeUndefined()
    expect(resultText({ ...executed, result: null })).toBeUndefined()
    expect(resultText({ ...executed, result: { found: true, text: 42 as never } })).toBeUndefined()
  })

  it('never shows a result the API sent for a call that did not run', () => {
    for (const tampered of [
      { ...executed, decision: 'Block' as const, outcome: 'Denied' as const, executed: false },
      { ...executed, decision: 'Review' as const },
      { ...executed, executed: false },
      { ...executed, outcome: 'ArgumentsRejected' as const },
    ]) {
      expect(resultText(tampered)).toBeUndefined()
    }
  })
})

describe('describeArguments', () => {
  it('shows the arguments as compact JSON, shortened only for display', () => {
    const request = { tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', arguments: { query: 'x'.repeat(100) } }

    expect(describeArguments({ ...request, arguments: { query: 'dependency injection' } })).toBe('{"query":"dependency injection"}')
    expect(describeArguments(request)).toHaveLength(60)
    expect(describeArguments(request).endsWith('…')).toBe(true)
    expect(request.arguments.query).toHaveLength(100)
  })
})

describe('presentToolGatewayError', () => {
  it('explains a missing permission and a server failure in the gateway’s own words', () => {
    const forbidden = presentToolGatewayError(new ApiError({ kind: 'http', status: 403, correlationId: 'corr-403', problem: { title: 'Server title zq7' } }))
    const failed = presentToolGatewayError(new ApiError({ kind: 'http', status: 500, problem: { title: 'Exception zq7', detail: 'zq7 stack' } }))

    expect(forbidden).toEqual({ title: 'You don’t have permission to execute tools', description: 'This client is signed in but not allowed to use the tool gateway.', reference: 'corr-403' })
    expect(failed.title).toBe('No result was returned')
    expect(JSON.stringify([forbidden, failed])).not.toContain('zq7')
  })

  it('falls back to the shared wording for everything else, without server text', () => {
    expect(presentToolGatewayError(new ApiError({ kind: 'http', status: 401, problem: { title: 'zq7' } })).title).toBe('Authentication required')
    expect(presentToolGatewayError(new ApiError({ kind: 'network' })).title).toBe('Can’t reach the AgentShield API')
    expect(presentToolGatewayError(new Error('zq7')).title).toBe('The preview couldn’t run')
  })
})

describe('toolGatewayExamples', () => {
  it('name no agent and assert no authority: the API key is the agent', () => {
    for (const example of toolGatewayExamples) {
      expect(Object.keys(example.request).every((key) => ['tool', 'action', 'capability', 'arguments', 'inputDecision'].includes(key))).toBe(true)
    }

    expect(new Set(toolGatewayExamples.map((example) => example.id)).size).toBe(toolGatewayExamples.length)
  })
})
