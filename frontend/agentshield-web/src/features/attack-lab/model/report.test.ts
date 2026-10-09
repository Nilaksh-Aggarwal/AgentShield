import { describe, expect, it } from 'vitest'
import { ApiError } from '@/services/api'
import type { ScenarioRun } from '../api/runScenario'
import { analysisResult, executionResult, stopped } from '../testFixtures'
import { buildSecurityReport, type SessionRun } from './report'
import { findScenario, type AttackScenario } from './scenarios'

function scenario(id: string): AttackScenario {
  const found = findScenario(id)
  if (!found) {
    throw new Error(`no scenario ${id}`)
  }

  return found
}

const generatedAt = new Date('2026-10-07T10:00:00Z')

function entryOf(run: SessionRun) {
  const [entry] = buildSecurityReport([run], generatedAt).entries
  if (!entry) {
    throw new Error('no entry')
  }

  return entry
}

describe('buildSecurityReport', () => {
  it('records each run as allowlisted metadata, in order, with a notice and no pass or fail field', () => {
    const runs: SessionRun[] = [
      { scenario: scenario('I-01'), run: { kind: 'input', scenarioId: 'I-01', result: analysisResult() } },
      { scenario: scenario('T-01'), run: { kind: 'tool', scenarioId: 'T-01', result: executionResult() } },
    ]

    const report = buildSecurityReport(runs, generatedAt)

    expect(report.report).toBe('AgentShield Attack Lab report')
    expect(report.notice).toContain('synthetic scenarios')
    expect(report.notice).toContain('Metadata only')
    expect(report.generatedAt).toBe('2026-10-07T10:00:00.000Z')
    expect(report.runs).toBe(2)
    expect(report.entries).toEqual([
      {
        scenarioId: 'I-01',
        title: 'Ignore your rules',
        category: 'Prompt injection',
        writtenToShow: 'Block',
        responses: [
          {
            endpoint: 'POST /api/v1/firewall/analyze',
            httpStatus: 200,
            decision: 'Block',
            riskLevel: 'Critical',
            riskScore: 95,
            findingCodes: ['InstructionOverride.IgnorePrevious', 'SecretExtraction.SystemPromptDisclosure'],
            toolRan: false,
            securityEventId: '0192a0f5-0000-7000-8000-00000000a001',
            correlationId: 'corr-lab-input',
            respondedAt: '2026-10-07T09:00:00.000Z',
          },
        ],
      },
      {
        scenarioId: 'T-01',
        title: 'Allowed lookup',
        category: 'Safe tool call',
        writtenToShow: 'Allow; the tool runs',
        responses: [
          {
            endpoint: 'POST /api/v1/agent/tools/execute',
            httpStatus: 200,
            decision: 'Allow',
            riskLevel: 'Low',
            authorizationReason: 'Permitted',
            outcome: 'Executed',
            toolRan: true,
            securityEventId: '0192a0f5-0000-7000-8000-00000000b001',
            correlationId: 'corr-lab-tool',
            respondedAt: '2026-10-07T09:00:01.000Z',
          },
        ],
      },
    ])
    expect(JSON.stringify(report)).not.toMatch(/"(pass|passed|fail|failed|matches|success)"/)
  })

  it('never copies inputs, arguments, tool results, reasons, descriptions or anything outside the allowlist', () => {
    const input = scenario('I-05')
    const tool = scenario('T-02')
    if (input.kind !== 'input' || tool.kind !== 'tool') {
      throw new Error('unexpected scenario kinds')
    }

    const report = buildSecurityReport(
      [
        {
          scenario: input,
          run: {
            kind: 'input',
            scenarioId: input.id,
            result: analysisResult({
              decision: 'zq7Block',
              reason: 'zq7 policy text',
              risk: { level: 'zq7', score: 'zq7' },
              findings: [
                { code: 'zq7 <script>', category: 'X', severity: 'High', confidence: 1, description: 'zq7 description' },
                { code: 'zq7 InstructionOverride.IgnorePrevious zq7', category: 'X', severity: 'High', confidence: 1, description: '' },
                { code: 'Obfuscation.EncodedInstruction', category: 'Obfuscation', severity: 'High', confidence: 1, description: 'zq7 decoded text' },
                { code: 'Obfuscation.EncodedInstruction', category: 'Obfuscation', severity: 'High', confidence: 1, description: 'zq7' },
              ],
              securityEventId: 'zq7 id with spaces',
              input: 'zq7 echoed input',
            }),
          },
        },
        {
          scenario: tool,
          run: {
            kind: 'tool',
            scenarioId: tool.id,
            result: {
              ...executionResult({
                ...stopped('Block', 'zq7Outcome', 'Policy.Zq7Rule'),
                riskLevel: 'constructor',
                arguments: { path: '/etc/passwd', query: 'zq7' },
                result: { found: true, text: 'zq7 result' },
                ruleId: 'AG-zq7',
              }),
              correlationId: `zq7-${'x'.repeat(80)}`,
              timestamp: 'zq7 not a time',
            },
          },
        },
      ],
      generatedAt,
    )

    const json = JSON.stringify(report)
    expect(json).not.toContain('zq7')
    expect(json).not.toContain('Zq7')
    expect(json).not.toContain('/etc/passwd')
    expect(json).not.toContain(injectionFrom(input))
    expect(json).not.toContain('Great product')
    const [first, second] = report.entries.map((entry) => entry.responses[0])
    expect(first?.decision).toBe('Unrecognised')
    expect(first?.riskLevel).toBe('Unrecognised')
    expect(first?.riskScore).toBeUndefined()
    expect(first?.findingCodes).toEqual(['Obfuscation.EncodedInstruction'])
    expect(first?.securityEventId).toBeUndefined()
    expect(second?.outcome).toBe('Unrecognised')
    expect(second?.authorizationReason).toBe('Unrecognised')
    expect(second?.riskLevel).toBe('Unrecognised')
    expect(second?.toolRan).toBe(false)
    expect(second?.correlationId).toBeUndefined()
    expect(second?.respondedAt).toBeUndefined()
  })

  it('records a tool as run only when the decision, the flag and the outcome all say so', () => {
    const ran = (overrides: Record<string, unknown>) =>
      entryOf({ scenario: scenario('T-01'), run: { kind: 'tool', scenarioId: 'T-01', result: executionResult(overrides) } }).responses[0]?.toolRan

    expect(ran({})).toBe(true)
    for (const overrides of [{ outcome: 'Denied' }, { decision: 'Block' }, { decision: 'Review' }, { executed: false }, { outcome: 'zq7' }]) {
      expect(ran(overrides)).toBe(false)
    }
  })

  it('records the replay as two responses: the allowed call, then the rejection before any decision', () => {
    const replay: ScenarioRun = {
      kind: 'replay',
      scenarioId: 'T-05',
      first: executionResult(),
      second: { status: 'rejected', httpStatus: 400, contractRejection: true, correlationId: 'corr-replay' },
    }

    const entry = entryOf({ scenario: scenario('T-05'), run: replay })

    expect(entry.responses).toHaveLength(2)
    expect(entry.responses[1]).toEqual({
      endpoint: 'POST /api/v1/agent/tools/execute',
      httpStatus: 400,
      rejectedBeforeDecision: true,
      errorCode: 'Request.Malformed',
      toolRan: false,
      correlationId: 'corr-replay',
    })
    expect(JSON.stringify(entry)).not.toContain('0192a0f5-0000-7000-8000-00000000e001')
  })

  it('records a failed second request as failed, with only its status and reference', () => {
    const failure = new ApiError({ kind: 'http', status: 429, problem: { title: 'zq7 title', detail: 'zq7 detail', correlationId: 'corr-429' }, retryAfterSeconds: 5 })
    const entry = entryOf({ scenario: scenario('T-05'), run: { kind: 'replay', scenarioId: 'T-05', first: executionResult(), second: { status: 'failed', error: failure } } })

    expect(entry.responses[1]).toEqual({ endpoint: 'POST /api/v1/agent/tools/execute', httpStatus: 429, failed: true, correlationId: 'corr-429' })
    expect(JSON.stringify(entry)).not.toContain('zq7')

    const network = entryOf({ scenario: scenario('T-05'), run: { kind: 'replay', scenarioId: 'T-05', first: executionResult(), second: { status: 'failed', error: new TypeError('zq7') } } })
    expect(network.responses[1]).toEqual({ endpoint: 'POST /api/v1/agent/tools/execute', httpStatus: undefined, failed: true, correlationId: undefined })
  })
})

function injectionFrom(scenario: AttackScenario): string {
  return scenario.kind === 'input' ? (scenario.hidden ?? scenario.input) : ''
}

describe('buildSecurityReport: the approval scenario', () => {
  const approvalId = '0192a0f5-0000-4000-8000-0000000000a4'
  const held = executionResult({ ...stopped('Review', 'HeldForReview', 'InputHeldForReview'), approvalId, riskLevel: 'Medium' })

  it('records the analysis, the held call, the decision and the presented call, as metadata only', () => {
    const run: ScenarioRun = {
      kind: 'approval',
      scenarioId: 'T-04',
      analysis: analysisResult({ decision: 'Review', risk: { level: 'Medium', score: 50 }, findings: [] }),
      held,
      decision: { action: 'approve', answer: 'Approved', correlationId: undefined },
      final: executionResult({ approvalId, authorizationReason: 'InputHeldForReview', result: { found: true, text: 'zq7 tool result' } }),
    }

    const entry = entryOf({ scenario: scenario('T-04'), run })

    expect(entry.writtenToShow).toBe('Review, held with a pending approval; approved, the call runs once; denied, it never runs')
    expect(entry.responses.map((response) => response.endpoint)).toEqual([
      'POST /api/v1/firewall/analyze',
      'POST /api/v1/agent/tools/execute',
      'POST /api/v1/agent/approvals/{id}/approve',
      'POST /api/v1/agent/tools/execute',
    ])
    expect(entry.responses.map((response) => response.toolRan)).toEqual([false, false, false, true])
    expect(entry.responses[1]).toMatchObject({ decision: 'Review', outcome: 'HeldForReview', authorizationReason: 'InputHeldForReview', riskLevel: 'Medium' })
    expect(entry.responses[2]).toEqual({ endpoint: 'POST /api/v1/agent/approvals/{id}/approve', approval: { action: 'approve', answer: 'Approved' }, toolRan: false, correlationId: undefined })
    const serialised = JSON.stringify(entry)
    expect(serialised).not.toContain('zq7')
    expect(serialised).not.toContain('fail closed')
    expect(serialised).not.toContain(approvalId)
  })

  it('records a pending approval as two responses, and an answer it does not know as such', () => {
    const pending = entryOf({ scenario: scenario('T-04'), run: { kind: 'approval', scenarioId: 'T-04', analysis: analysisResult(), held } })
    expect(pending.responses).toHaveLength(2)

    const odd = entryOf({
      scenario: scenario('T-04'),
      run: {
        kind: 'approval',
        scenarioId: 'T-04',
        analysis: analysisResult(),
        held,
        decision: { action: 'deny', answer: 'zq7' as 'Denied', correlationId: 'corr-deny' },
        final: executionResult({ ...stopped('Block', 'ApprovalRejected', 'InputHeldForReview'), approvalId }),
      },
    })
    expect(odd.responses[2]).toEqual({ endpoint: 'POST /api/v1/agent/approvals/{id}/deny', approval: { action: 'deny', answer: 'Unrecognised' }, toolRan: false, correlationId: 'corr-deny' })
    expect(odd.responses[3]).toMatchObject({ decision: 'Block', outcome: 'ApprovalRejected', toolRan: false })
    expect(JSON.stringify(odd)).not.toContain('zq7')
  })
})
