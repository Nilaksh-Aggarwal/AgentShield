import { toolRan, type ToolExecutionResult } from '@/features/agents'
import { isApiError } from '@/services/api'
import type { FirewallAnalysisResult } from '@/features/firewall'
import type { ApprovalDecision, ReplayAttempt, ScenarioRun } from '../api/runScenario'
import { describeIntent, riskScore } from './evidence'
import type { AttackScenario } from './scenarios'

/** One run of this visit: the scenario and what the API returned for it. */
export interface SessionRun {
  scenario: AttackScenario
  run: ScenarioRun
}

/**
 * A response as the report records it: allowlisted metadata only. Every value is either one of a fixed set of names or
 * an identifier, code or time that passed a strict format check; anything else becomes "Unrecognised" or is left out.
 * There is never an input, a decoded text, a tool argument, a tool result, a policy reason text or a server message.
 */
export interface ReportResponse {
  endpoint: string
  /** Absent when no HTTP response arrived (network failure, timeout). */
  httpStatus?: number
  decision?: string
  riskLevel?: string
  riskScore?: number
  findingCodes?: string[]
  authorizationReason?: string
  outcome?: string
  toolRan?: boolean
  rejectedBeforeDecision?: boolean
  /** The request failed for another reason (rate limit, network): nothing to report but that. */
  failed?: boolean
  errorCode?: string
  /** For the approval endpoint: the person's action and what the endpoint answered. */
  approval?: { action: 'approve' | 'deny'; answer: string }
  securityEventId?: string
  correlationId?: string
  respondedAt?: string
}

export interface ReportEntry {
  scenarioId: string
  title: string
  category: string
  /** What the scenario was written to show: the console's own text, kept apart from the API's responses. */
  writtenToShow: string
  responses: ReportResponse[]
}

export interface SecurityReport {
  report: 'AgentShield Attack Lab report'
  notice: string
  generatedAt: string
  runs: number
  entries: ReportEntry[]
}

const firewallEndpoint = 'POST /api/v1/firewall/analyze'
const gatewayEndpoint = 'POST /api/v1/agent/tools/execute'

const decisions = new Set(['Allow', 'Review', 'Block'])
const riskLevels = new Set(['Low', 'Medium', 'High', 'Critical'])
const outcomes = new Set(['Executed', 'HeldForReview', 'Denied', 'ArgumentsRejected', 'ToolUnavailable', 'ExecutionAuthorizationRejected', 'ExecutionFailed', 'InputContextRejected', 'ApprovalRejected'])
const reasons = new Set([
  'Permitted',
  'HumanApprovalRequired',
  'InputHeldForReview',
  'UnknownAgent',
  'UnknownTool',
  'UnknownAction',
  'CapabilityMismatch',
  'CapabilityNotGranted',
  'CriticalActionDenied',
  'InputBlocked',
  'CallerNotBoundToAgent',
])

// Public finding codes are `Category.Reason`; identifiers use the API's correlation ID alphabet and length (at most 64 of
// `[A-Za-z0-9._:-]`). Anything else is not copied.
const findingCode = /^[A-Za-z]{1,64}\.[A-Za-z]{1,64}$/
const identifier = /^[A-Za-z0-9._:-]{1,64}$/

function named(set: ReadonlySet<string>, value: unknown): string {
  return typeof value === 'string' && set.has(value) ? value : 'Unrecognised'
}

function id(value: unknown): string | undefined {
  return typeof value === 'string' && identifier.test(value) ? value : undefined
}

function time(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString()
}

function analysisResponse({ analysis, correlationId, timestamp }: FirewallAnalysisResult): ReportResponse {
  const codes = Array.isArray(analysis.findings)
    ? analysis.findings.map((finding) => finding?.code).filter((code): code is string => typeof code === 'string' && findingCode.test(code))
    : []
  return {
    endpoint: firewallEndpoint,
    httpStatus: 200,
    decision: named(decisions, analysis.decision),
    riskLevel: named(riskLevels, analysis.risk?.level),
    riskScore: riskScore(analysis.risk?.score),
    findingCodes: [...new Set(codes)],
    toolRan: false,
    securityEventId: id(analysis.securityEventId),
    correlationId: id(correlationId),
    respondedAt: time(timestamp),
  }
}

function executionResponse({ execution, correlationId, timestamp }: ToolExecutionResult): ReportResponse {
  return {
    endpoint: gatewayEndpoint,
    httpStatus: 200,
    decision: named(decisions, execution.decision),
    riskLevel: named(riskLevels, execution.riskLevel),
    authorizationReason: named(reasons, execution.authorizationReason),
    outcome: named(outcomes, execution.outcome),
    // The page's rule: the tool ran only when the decision, the flag and the outcome all say so.
    toolRan: toolRan(execution),
    securityEventId: id(execution.securityEventId),
    correlationId: id(correlationId),
    respondedAt: time(timestamp),
  }
}

function replayResponse(second: ReplayAttempt): ReportResponse {
  if (second.status === 'accepted') {
    return executionResponse(second.result)
  }

  if (second.status === 'failed') {
    const { error } = second
    const status = isApiError(error) && error.kind === 'http' ? error.status : undefined
    return {
      endpoint: gatewayEndpoint,
      httpStatus: typeof status === 'number' && Number.isInteger(status) ? status : undefined,
      failed: true,
      correlationId: isApiError(error) ? id(error.correlationId) : undefined,
    }
  }

  return {
    endpoint: gatewayEndpoint,
    httpStatus: second.httpStatus,
    rejectedBeforeDecision: second.contractRejection,
    errorCode: second.contractRejection ? 'Request.Malformed' : undefined,
    toolRan: false,
    correlationId: id(second.correlationId),
  }
}

const approvalAnswers = new Set(['Approved', 'Denied', 'Expired', 'AlreadyDecided', 'NotFound'])

function approvalResponse(decision: ApprovalDecision): ReportResponse {
  return {
    endpoint: `POST /api/v1/agent/approvals/{id}/${decision.action === 'approve' ? 'approve' : 'deny'}`,
    approval: { action: decision.action === 'approve' ? 'approve' : 'deny', answer: named(approvalAnswers, decision.answer) },
    toolRan: false,
    correlationId: id(decision.correlationId),
  }
}

function responses(run: ScenarioRun): ReportResponse[] {
  switch (run.kind) {
    case 'input':
      return [analysisResponse(run.result)]
    case 'tool':
      return [executionResponse(run.result)]
    case 'replay':
      return [executionResponse(run.first), replayResponse(run.second)]
    case 'approval':
      return [
        analysisResponse(run.analysis),
        executionResponse(run.held),
        ...(run.decision === undefined ? [] : [approvalResponse(run.decision)]),
        ...(run.final === undefined ? [] : [executionResponse(run.final)]),
      ]
  }
}

/**
 * The visit's runs as a metadata-only report. There is deliberately no pass/fail field: the report records what the API
 * returned, and the scenario's intent is kept apart from it.
 */
export function buildSecurityReport(runs: readonly SessionRun[], generatedAt: Date): SecurityReport {
  return {
    report: 'AgentShield Attack Lab report',
    notice:
      'Development console, synthetic scenarios, run against the live API as the public Development client. Metadata only: no inputs, tool arguments, tool results or server messages.',
    generatedAt: generatedAt.toISOString(),
    runs: runs.length,
    entries: runs.map(({ scenario, run }) => ({
      scenarioId: scenario.id,
      title: scenario.title,
      category: scenario.category,
      writtenToShow: describeIntent(scenario),
      responses: responses(run),
    })),
  }
}
