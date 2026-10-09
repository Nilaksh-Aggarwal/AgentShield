import { describe, expect, it } from 'vitest'
import type { ApprovalDecision, ApprovalRun, ScenarioRun } from '../api/runScenario'
import { analysis, analysisResult, execution, executionResult, stopped } from '../testFixtures'
import {
  approvalTrail,
  compareWithIntent,
  describeIntent,
  inputTrail,
  presentApprovalDecision,
  presentRunDecision,
  presentRunRisk,
  replayStep,
  riskScore,
  runDecision,
  runExecutedTool,
  toolTrail,
} from './evidence'
import { findScenario, type AttackScenario } from './scenarios'

function scenario(id: string): AttackScenario {
  const found = findScenario(id)
  if (!found) {
    throw new Error(`no scenario ${id}`)
  }

  return found
}

const text = (steps: readonly { label: string; value: string }[]) => steps.map((step) => `${step.label}: ${step.value}`).join(' | ')

describe('presentRunDecision / presentRunRisk / riskScore', () => {
  it('know the three decisions and four levels, and echo nothing else', () => {
    expect(presentRunDecision('Allow')).toEqual({ label: 'Allow', tone: 'success', known: true })
    expect(presentRunDecision('Block').tone).toBe('danger')
    for (const value of ['allow', 'Allowed', 'zq7', 'constructor', '__proto__', '', null, 3, { label: 'Allow' }]) {
      expect(presentRunDecision(value)).toEqual({ label: 'Not recognised', tone: 'warning', known: false })
      expect(presentRunRisk(value).label).toBe('Unknown risk')
    }

    expect(presentRunRisk('Critical')).toEqual({ label: 'Critical risk', tone: 'critical' })
  })

  it('accept only an integer score from 0 to 100', () => {
    expect([0, 42, 100].map(riskScore)).toEqual([0, 42, 100])
    expect([-1, 101, 4.5, Number.NaN, '50', null].map(riskScore)).toEqual([undefined, undefined, undefined, undefined, undefined, undefined])
  })
})

describe('inputTrail', () => {
  it('reports detect, score and decide from the analysis, and that no tool is involved', () => {
    expect(text(inputTrail(analysis()))).toBe(
      'Detect: 2 findings | Score: Critical risk, 95 / 100 | Decide: Block: Do not forward to the agent | Tool: Not involved: input analysis decides; it runs nothing',
    )
    expect(text(inputTrail(analysis({ decision: 'Allow', risk: { level: 'Low', score: 0 }, findings: [] })))).toContain(
      'Detect: Nothing detected | Score: Low risk, 0 / 100 | Decide: Allow: Safe to forward',
    )
  })

  it('never echoes or trusts values it does not know', () => {
    const steps = inputTrail(analysis({ decision: 'zq7Allow', risk: { level: 'zq7Level', score: 'zq7' }, findings: 'zq7' }))
    expect(text(steps)).not.toContain('zq7')
    expect(text(steps)).toContain('Decide: Not recognised: hold for review')
    expect(text(steps)).toContain('Score: Unknown risk')
    expect(text(steps)).toContain('Detect: Nothing detected')
  })
})

describe('toolTrail', () => {
  it('shows an executed call as authorised, accepted, granted and run once', () => {
    expect(text(toolTrail(execution()))).toBe(
      'Authorize: Permitted (Low risk) | Arguments: Accepted by the tool’s schema | Grant: Single-use grant issued, checked and consumed | Execute: The tool ran once',
    )
  })

  it.each([
    ['ArgumentsRejected', 'Block', 'Permitted', 'Arguments: Rejected: outside the tool’s schema', 'Arguments rejected'],
    ['Denied', 'Block', 'CapabilityNotGranted', 'Arguments: Not checked: the call was not authorised', 'Blocked'],
    ['HeldForReview', 'Review', 'HumanApprovalRequired', 'Arguments: Not checked: the call was not authorised', 'Held for review'],
    ['ToolUnavailable', 'Block', 'Permitted', 'Arguments: Not checked: no tool here runs this action', 'No tool to run'],
    ['ExecutionAuthorizationRejected', 'Block', 'Permitted', 'Grant: Grant refused', 'Grant refused'],
  ])('shows %s as a tool that did not run', (outcome, decision, reason, step, label) => {
    const trail = text(toolTrail(execution(stopped(decision, outcome, reason))))
    expect(trail).toContain(step)
    expect(trail).toContain(`Execute: The tool did not run (${label})`)
  })

  it('shows a tool as run only when the decision, the flag and the outcome all say so', () => {
    for (const overrides of [{ decision: 'Block' }, { decision: 'Review' }, { executed: false }, { outcome: 'Denied' }, { executed: 'true' }, { decision: 'zq7' }]) {
      expect(text(toolTrail(execution(overrides)))).toContain('Execute: The tool did not run')
    }
  })

  it('never echoes an unknown reason, level or outcome', () => {
    const trail = text(toolTrail(execution({ authorizationReason: 'zq7Reason', riskLevel: 'zq7', outcome: 'zq7Outcome' })))
    expect(trail).not.toContain('zq7')
    expect(trail).toContain('Authorize: Not recognised (Unknown risk)')
    expect(trail).toContain('Arguments: Not reported')
    expect(trail).toContain('Execute: The tool did not run (Not recognised)')
  })
})

describe('replayStep', () => {
  it('describes a contract rejection, another rejection, an acceptance and a failure, honestly', () => {
    expect(replayStep({ status: 'rejected', httpStatus: 400, contractRejection: true, correlationId: 'c' }).value).toBe(
      'Rejected before any decision (HTTP 400): the request carried an authorization claim; nothing ran',
    )
    expect(replayStep({ status: 'rejected', httpStatus: 400, contractRejection: false, correlationId: undefined }).value).toBe('Rejected (HTTP 400); nothing was decided')
    expect(replayStep({ status: 'accepted', result: executionResult() })).toEqual({ label: 'Replay', value: 'Accepted: Allow, the tool ran', tone: 'warning' })
    expect(replayStep({ status: 'failed', error: new Error('zq7') }).value).not.toContain('zq7')
  })
})

describe('compareWithIntent', () => {
  const input = (overrides: Record<string, unknown>): ScenarioRun => ({ kind: 'input', scenarioId: 'I-01', result: analysisResult(overrides) })
  const tool = (id: string, overrides: Record<string, unknown>): ScenarioRun => ({ kind: 'tool', scenarioId: id, result: executionResult(overrides) })

  it('compares the API decision with the intent, informationally', () => {
    expect(compareWithIntent(scenario('I-01'), input({ decision: 'Block' }))).toBe('matches')
    expect(compareWithIntent(scenario('I-01'), input({ decision: 'Allow' }))).toBe('differs')
    expect(compareWithIntent(scenario('I-01'), input({ decision: 'zq7' }))).toBe('unknown')
    expect(compareWithIntent(scenario('T-01'), tool('T-01', {}))).toBe('matches')
    expect(compareWithIntent(scenario('T-01'), tool('T-01', { outcome: 'ExecutionFailed', executed: true }))).toBe('differs')
    expect(compareWithIntent(scenario('T-02'), tool('T-02', stopped('Block', 'ArgumentsRejected', 'Permitted')))).toBe('matches')
    expect(compareWithIntent(scenario('T-02'), tool('T-02', {}))).toBe('differs')
    expect(compareWithIntent(scenario('T-02'), tool('T-02', { decision: 'constructor' }))).toBe('unknown')
  })

  it('cannot compare a run with another scenario or kind', () => {
    expect(compareWithIntent(scenario('I-02'), input({}))).toBe('unknown')
    expect(compareWithIntent(scenario('T-01'), { kind: 'input', scenarioId: 'T-01', result: analysisResult() })).toBe('unknown')
  })

  it('needs the replay to run once and then be rejected', () => {
    const replay = (second: Extract<ScenarioRun, { kind: 'replay' }>['second']): ScenarioRun => ({ kind: 'replay', scenarioId: 'T-05', first: executionResult(), second })
    expect(compareWithIntent(scenario('T-05'), replay({ status: 'rejected', httpStatus: 400, contractRejection: true, correlationId: 'c' }))).toBe('matches')
    expect(compareWithIntent(scenario('T-05'), replay({ status: 'accepted', result: executionResult() }))).toBe('differs')
    expect(compareWithIntent(scenario('T-05'), replay({ status: 'failed', error: new Error() }))).toBe('differs')
  })
})

describe('runDecision / runExecutedTool', () => {
  it('take the decision from the response, and count a tool as run only through the gateway with every field agreeing', () => {
    expect(runDecision({ kind: 'input', scenarioId: 'I-01', result: analysisResult() }).label).toBe('Block')
    expect(runExecutedTool({ kind: 'input', scenarioId: 'I-01', result: analysisResult({ decision: 'Allow', executed: true, outcome: 'Executed' }) })).toBe(false)
    expect(runExecutedTool({ kind: 'tool', scenarioId: 'T-01', result: executionResult() })).toBe(true)
    expect(runExecutedTool({ kind: 'tool', scenarioId: 'T-01', result: executionResult({ outcome: 'Denied' }) })).toBe(false)

    const accepted: ScenarioRun = { kind: 'replay', scenarioId: 'T-05', first: executionResult({ decision: 'Block', executed: false, outcome: 'Denied' }), second: { status: 'accepted', result: executionResult() } }
    expect(runExecutedTool(accepted)).toBe(true)
    expect(runDecision(accepted).label).toBe('Block')
  })
})

describe('the approval scenario: compareWithIntent, approvalTrail, presentApprovalDecision', () => {
  const approvalId = '0192a0f5-0000-4000-8000-0000000000a4'
  const held = executionResult({ ...stopped('Review', 'HeldForReview', 'InputHeldForReview'), approvalId, riskLevel: 'Medium' })
  const ranOnce = executionResult({ approvalId, authorizationReason: 'InputHeldForReview' })
  const refused = executionResult({ ...stopped('Block', 'ApprovalRejected', 'InputHeldForReview'), approvalId })
  const decided = (answer: ApprovalDecision['answer'], action: ApprovalDecision['action'] = 'approve'): ApprovalDecision => ({ action, answer, correlationId: undefined })

  function approval(overrides: Partial<ApprovalRun> = {}): ApprovalRun {
    return { kind: 'approval', scenarioId: 'T-04', analysis: analysisResult({ decision: 'Review', risk: { level: 'Medium', score: 50 } }), held, ...overrides }
  }

  it('matches only a held call, then only an approval that ran or a refusal that did not', () => {
    const t04 = scenario('T-04')
    expect(compareWithIntent(t04, approval())).toBe('matches')
    expect(compareWithIntent(t04, approval({ decision: decided('Approved'), final: ranOnce }))).toBe('matches')
    expect(compareWithIntent(t04, approval({ decision: decided('Denied', 'deny'), final: refused }))).toBe('matches')
    expect(compareWithIntent(t04, approval({ decision: decided('Expired'), final: refused }))).toBe('matches')

    expect(compareWithIntent(t04, approval({ decision: decided('Approved'), final: refused }))).toBe('differs')
    expect(compareWithIntent(t04, approval({ decision: decided('Denied', 'deny'), final: ranOnce }))).toBe('differs')
    expect(compareWithIntent(t04, approval({ decision: decided('Expired'), final: ranOnce }))).toBe('differs')
    expect(compareWithIntent(t04, approval({ held: executionResult() }))).toBe('differs')
    expect(compareWithIntent(t04, approval({ held: executionResult({ ...stopped('Review', 'HeldForReview', 'InputHeldForReview'), approvalId: null }) }))).toBe('differs')
    expect(compareWithIntent(scenario('T-01'), approval())).toBe('unknown')
  })

  it('traces a pending approval: the server’s input decision, the verdict, pending, nothing run', () => {
    expect(text(approvalTrail(approval()))).toBe(
      'Input: Firewall: Review (the server’s record; the agent claimed Allow) | Authorize: Input under review (Medium risk) | Approval: Pending: a person must decide | Execute: Nothing runs until a person approves',
    )
  })

  it('traces an approval that ran once, and a denial or expiry that ran nothing', () => {
    expect(text(approvalTrail(approval({ decision: decided('Approved'), final: ranOnce })))).toContain('Approval: Approved | Execute: The tool ran once, with the approval')
    expect(text(approvalTrail(approval({ decision: decided('Denied', 'deny'), final: refused })))).toContain('Approval: Denied | Execute: The tool did not run (Approval rejected)')
    expect(text(approvalTrail(approval({ decision: decided('Expired'), final: refused })))).toContain('Approval: Expired before it was decided | Execute: The tool did not run')
  })

  it('never shows a run the final response does not confirm in every field, nor an approval the gateway did not create', () => {
    const tampered = executionResult({ approvalId, decision: 'Allow', executed: true, outcome: 'ApprovalRejected' })
    expect(text(approvalTrail(approval({ decision: decided('Approved'), final: tampered })))).toContain('Execute: The tool did not run')
    expect(text(approvalTrail(approval({ held: executionResult({ ...stopped('Review', 'HeldForReview', 'InputHeldForReview'), approvalId: null }) })))).toContain(
      'Approval: No approval created',
    )
    expect(text(approvalTrail(approval({ analysis: analysisResult({ decision: 'zq7' }) })))).toContain('Input: Firewall decision not recognised')
  })

  it('presents each answer of the approval endpoint, and nothing it does not know', () => {
    expect(
      (['Approved', 'Denied', 'Expired', 'AlreadyDecided', 'NotFound', 'Unrecognised'] as const).map((answer) => presentApprovalDecision(decided(answer)).label),
    ).toEqual(['Approved', 'Denied', 'Expired before it was decided', 'Already decided', 'No such approval', 'Not recognised'])
    expect(presentApprovalDecision(decided('zq7' as ApprovalDecision['answer'])).label).toBe('Not recognised')
  })

  it('take the final decision once there is one, and count only the gateway’s confirmed run', () => {
    expect(runDecision(approval()).label).toBe('Review')
    expect(runDecision(approval({ decision: decided('Approved'), final: ranOnce })).label).toBe('Allow')
    expect(runExecutedTool(approval())).toBe(false)
    expect(runExecutedTool(approval({ decision: decided('Approved'), final: ranOnce }))).toBe(true)
    expect(runExecutedTool(approval({ decision: decided('Denied', 'deny'), final: refused }))).toBe(false)
    expect(describeIntent(scenario('T-04'))).toBe('Review, held with a pending approval; approved, the call runs once; denied, it never runs')
  })
})
