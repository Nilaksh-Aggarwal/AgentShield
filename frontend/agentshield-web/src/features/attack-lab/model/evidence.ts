import type { ToolExecution } from '@/features/agents'
import { presentActionDecision, presentAgentActionReason, presentToolOutcome, toolRan } from '@/features/agents'
import type { FirewallAnalysis } from '@/features/firewall'
import { presentDecision } from '@/features/firewall'
import type { Tone } from '@/shared/components/ui'
import type { ApprovalDecision, ApprovalRun, ReplayAttempt, ScenarioRun } from '../api/runScenario'
import type { AttackScenario } from './scenarios'

// Own-property lookups only (D-17): an API value such as "constructor" must not select an inherited member.
function own<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined
}

export interface Presentation {
  label: string
  tone: Tone
}

const decisions: Readonly<Record<string, Presentation>> = {
  Allow: { label: 'Allow', tone: 'success' },
  Review: { label: 'Review', tone: 'warning' },
  Block: { label: 'Block', tone: 'danger' },
}

/** A decision from the API. One the console does not know is never echoed and never shown as Allow. */
export function presentRunDecision(decision: unknown): Presentation & { known: boolean } {
  const entry = own(decisions, decision)
  return entry ? { ...entry, known: true } : { label: 'Not recognised', tone: 'warning', known: false }
}

const riskLevels: Readonly<Record<string, Presentation>> = {
  Low: { label: 'Low risk', tone: 'success' },
  Medium: { label: 'Medium risk', tone: 'warning' },
  High: { label: 'High risk', tone: 'danger' },
  Critical: { label: 'Critical risk', tone: 'critical' },
}

/** A risk level from the API. One the console does not know is not echoed. */
export function presentRunRisk(level: unknown): Presentation {
  return own(riskLevels, level) ?? { label: 'Unknown risk', tone: 'neutral' }
}

/** A risk score, only when it is one: an integer from 0 to 100. */
export function riskScore(score: unknown): number | undefined {
  return typeof score === 'number' && Number.isInteger(score) && score >= 0 && score <= 100 ? score : undefined
}

/** One stage of a run's trail: what that stage did, as the API's response says. */
export interface TrailStep {
  label: string
  value: string
  tone: Tone
}

/** Input security: DETECT → SCORE → DECIDE. No tool is involved: the firewall decides; the caller acts on its decision. */
export function inputTrail(analysis: FirewallAnalysis): TrailStep[] {
  const decision = presentRunDecision(analysis.decision)
  const risk = presentRunRisk(analysis.risk?.level)
  const score = riskScore(analysis.risk?.score)
  const count = Array.isArray(analysis.findings) ? analysis.findings.length : 0
  return [
    {
      label: 'Detect',
      value: count === 0 ? 'Nothing detected' : `${count} ${count === 1 ? 'finding' : 'findings'}`,
      tone: count === 0 ? 'success' : 'warning',
    },
    { label: 'Score', value: score === undefined ? risk.label : `${risk.label}, ${score} / 100`, tone: risk.tone },
    {
      label: 'Decide',
      value: decision.known ? `${decision.label}: ${presentDecision(decision.label).action}` : 'Not recognised: hold for review',
      tone: decision.tone,
    },
    { label: 'Tool', value: 'Not involved: input analysis decides; it runs nothing', tone: 'neutral' },
  ]
}

const authorizationTone: Readonly<Record<string, Tone>> = {
  Permitted: 'success',
  HumanApprovalRequired: 'warning',
  InputHeldForReview: 'warning',
}

const schemaAccepted = { value: 'Accepted by the tool’s schema', tone: 'success' } as const
const notChecked = { value: 'Not checked: the call was not authorised', tone: 'neutral' } as const

const argumentsStep: Readonly<Record<string, Omit<TrailStep, 'label'>>> = {
  Executed: schemaAccepted,
  ExecutionFailed: schemaAccepted,
  ExecutionAuthorizationRejected: schemaAccepted,
  ArgumentsRejected: { value: 'Rejected: outside the tool’s schema', tone: 'danger' },
  ToolUnavailable: { value: 'Not checked: no tool here runs this action', tone: 'neutral' },
  HeldForReview: notChecked,
  Denied: notChecked,
  InputContextRejected: notChecked,
  ApprovalRejected: notChecked,
}

const grantStep: Readonly<Record<string, Omit<TrailStep, 'label'>>> = {
  Executed: { value: 'Single-use grant issued, checked and consumed', tone: 'success' },
  ExecutionFailed: { value: 'Single-use grant issued and consumed', tone: 'success' },
  ExecutionAuthorizationRejected: { value: 'Grant refused', tone: 'danger' },
}

/** Agent security: AUTHORIZE → ARGUMENTS → GRANT → EXECUTE, from the gateway's response. Unknown values are not echoed. */
export function toolTrail(execution: ToolExecution): TrailStep[] {
  const reason = presentAgentActionReason(execution.authorizationReason)
  const risk = presentRunRisk(execution.riskLevel)
  const ran = toolRan(execution)
  return [
    { label: 'Authorize', value: `${reason.label} (${risk.label})`, tone: own(authorizationTone, execution.authorizationReason) ?? 'danger' },
    { label: 'Arguments', ...(own(argumentsStep, execution.outcome) ?? { value: 'Not reported', tone: 'warning' }) },
    { label: 'Grant', ...(own(grantStep, execution.outcome) ?? { value: 'No grant issued', tone: 'neutral' }) },
    { label: 'Execute', value: ran ? 'The tool ran once' : `The tool did not run (${presentToolOutcome(execution.outcome).label})`, tone: ran ? 'success' : 'neutral' },
  ]
}

/** The replay scenario's second request as one trail step. */
export function replayStep(second: ReplayAttempt): TrailStep {
  if (second.status === 'rejected') {
    return {
      label: 'Replay',
      value: second.contractRejection
        ? `Rejected before any decision (HTTP ${second.httpStatus}): the request carried an authorization claim; nothing ran`
        : `Rejected (HTTP ${second.httpStatus}); nothing was decided`,
      tone: 'danger',
    }
  }

  if (second.status === 'failed') {
    return { label: 'Replay', value: 'Not completed: the second request failed, so nothing was decided for it (see below)', tone: 'warning' }
  }

  const execution = second.result.execution
  return {
    label: 'Replay',
    value: `Accepted: ${presentActionDecision(execution.decision).label}, the tool ${toolRan(execution) ? 'ran' : 'did not run'}`,
    tone: 'warning',
  }
}

export type IntentComparison = 'matches' | 'differs' | 'unknown'

/**
 * Whether what the API returned is what the scenario was written to show. Informational only: the page always shows the
 * API's result, and a difference never changes it. A decision the console does not know cannot be compared.
 */
export function compareWithIntent(scenario: AttackScenario, run: ScenarioRun): IntentComparison {
  if (run.scenarioId !== scenario.id) {
    return 'unknown'
  }

  if (scenario.kind === 'input' && run.kind === 'input') {
    const decision = presentRunDecision(run.result.analysis.decision)
    return decision.known ? (decision.label === scenario.intent ? 'matches' : 'differs') : 'unknown'
  }

  if (scenario.kind === 'tool' && run.kind === 'tool') {
    const execution = run.result.execution
    const decision = presentRunDecision(execution.decision)
    if (!decision.known) {
      return 'unknown'
    }

    return decision.label === scenario.intent.decision && toolRan(execution) === scenario.intent.toolRuns ? 'matches' : 'differs'
  }

  if (scenario.kind === 'replay' && run.kind === 'replay') {
    return toolRan(run.first.execution) && run.second.status === 'rejected' ? 'matches' : 'differs'
  }

  if (scenario.kind === 'approval' && run.kind === 'approval') {
    const held = run.held.execution
    if (held.outcome !== 'HeldForReview' || typeof held.approvalId !== 'string') {
      return 'differs'
    }

    // Before a decision: held, as written. After: an approval runs the call once; anything else runs nothing.
    if (run.decision === undefined || run.final === undefined) {
      return 'matches'
    }

    const ran = toolRan(run.final.execution)
    return (run.decision.answer === 'Approved') === ran ? 'matches' : 'differs'
  }

  return 'unknown'
}

/** What a person's decision came to, in words: the endpoint's answer, never assumed. */
export function presentApprovalDecision(decision: ApprovalDecision): Presentation {
  switch (decision.answer) {
    case 'Approved':
      return { label: 'Approved', tone: 'success' }
    case 'Denied':
      return { label: 'Denied', tone: 'danger' }
    case 'Expired':
      return { label: 'Expired before it was decided', tone: 'danger' }
    case 'AlreadyDecided':
      return { label: 'Already decided', tone: 'warning' }
    case 'NotFound':
      return { label: 'No such approval', tone: 'warning' }
    default:
      return { label: 'Not recognised', tone: 'warning' }
  }
}

/** The approval scenario: the input's verified decision, the boundary's verdict, the person's decision, and what ran. */
export function approvalTrail(run: ApprovalRun): TrailStep[] {
  const input = presentRunDecision(run.analysis.analysis.decision)
  const held = run.held.execution
  const reason = presentAgentActionReason(held.authorizationReason)
  const risk = presentRunRisk(held.riskLevel)
  const pending = held.outcome === 'HeldForReview' && typeof held.approvalId === 'string'
  const decision = run.decision === undefined ? undefined : presentApprovalDecision(run.decision)
  const ran = run.final !== undefined && toolRan(run.final.execution)
  return [
    {
      label: 'Input',
      value: input.known ? `Firewall: ${input.label} (the server’s record; the agent claimed Allow)` : 'Firewall decision not recognised',
      tone: input.tone,
    },
    { label: 'Authorize', value: `${reason.label} (${risk.label})`, tone: held.decision === 'Review' ? 'warning' : 'danger' },
    {
      label: 'Approval',
      value: decision ? decision.label : pending ? 'Pending: a person must decide' : 'No approval created',
      tone: decision ? decision.tone : pending ? 'warning' : 'neutral',
    },
    {
      label: 'Execute',
      value: run.final === undefined
        ? 'Nothing runs until a person approves'
        : ran
          ? 'The tool ran once, with the approval'
          : `The tool did not run (${presentToolOutcome(run.final.execution.outcome).label})`,
      tone: ran ? 'success' : 'neutral',
    },
  ]
}

/** What the scenario was written to show, in words: displayed next to the result, never instead of it. */
export function describeIntent(scenario: AttackScenario): string {
  switch (scenario.kind) {
    case 'input':
      return scenario.intent
    case 'tool':
      return `${scenario.intent.decision}; the tool ${scenario.intent.toolRuns ? 'runs' : 'does not run'}`
    case 'replay':
      return 'The lookup is allowed and runs; presenting its execution ID is rejected'
    case 'approval':
      return 'Review, held with a pending approval; approved, the call runs once; denied, it never runs'
  }
}

/** The decision the API returned for a run, for summaries: the first request's, for the replay scenario. */
export function runDecision(run: ScenarioRun): Presentation & { known: boolean } {
  switch (run.kind) {
    case 'input':
      return presentRunDecision(run.result.analysis.decision)
    case 'tool':
      return presentRunDecision(run.result.execution.decision)
    case 'replay':
      return presentRunDecision(run.first.execution.decision)
    case 'approval':
      return presentRunDecision((run.final ?? run.held).execution.decision)
  }
}

/** Whether the run executed a tool. Only the gateway can, and only when every field of its response says so. */
export function runExecutedTool(run: ScenarioRun): boolean {
  switch (run.kind) {
    case 'input':
      return false
    case 'tool':
      return toolRan(run.result.execution)
    case 'replay':
      return toolRan(run.first.execution) || (run.second.status === 'accepted' && toolRan(run.second.result.execution))
    case 'approval':
      return toolRan(run.held.execution) || (run.final !== undefined && toolRan(run.final.execution))
  }
}
