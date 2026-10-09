import { decideApproval, executeToolTraced, type ToolExecutionRequest, type ToolExecutionResult } from '@/features/agents'
import { analyzeInput, type FirewallAnalysisResult } from '@/features/firewall'
import { apiClient, isApiError } from '@/services/api'
import type { ApprovalScenario, AttackScenario, ReplayScenario } from '../model/scenarios'

/** What one scenario run got back from the real API. Nothing here is computed by the console. */
export type ScenarioRun =
  | { kind: 'input'; scenarioId: string; result: FirewallAnalysisResult }
  | { kind: 'tool'; scenarioId: string; result: ToolExecutionResult }
  | { kind: 'replay'; scenarioId: string; first: ToolExecutionResult; second: ReplayAttempt }
  | ApprovalRun

/** The second request of the replay scenario: refused by the API (as intended), or — if it ever were — accepted. */
export type ReplayAttempt =
  | {
      status: 'rejected'
      httpStatus: number
      /** The API's stable error code said the request broke the contract (`Request.Malformed`). */
      contractRejection: boolean
      correlationId: string | undefined
    }
  | { status: 'accepted'; result: ToolExecutionResult }
  | { status: 'failed'; error: unknown }

/**
 * The approval scenario: the analysis of the input, the call the gateway held (with its pending approval, if it created
 * one), then, once a person decided, what the approval endpoint said and what the gateway did with the approved call.
 */
export interface ApprovalRun {
  kind: 'approval'
  scenarioId: string
  analysis: FirewallAnalysisResult
  held: ToolExecutionResult
  decision?: ApprovalDecision
  /** The gateway's answer when the agent presented the approval with the same call. */
  final?: ToolExecutionResult
}

/**
 * A person's decision as the approval endpoint answered it: the approval's status afterwards, or the conflict it reported
 * (already decided, expired). The console never assumes a status the API did not return.
 */
export interface ApprovalDecision {
  action: 'approve' | 'deny'
  /** The status the API returned, or the reason it refused the decision. */
  answer: 'Approved' | 'Denied' | 'Expired' | 'AlreadyDecided' | 'NotFound' | 'Unrecognised'
  correlationId: string | undefined
}

/**
 * Sends a scenario to the real AgentShield API: an input to the firewall, a tool call to the tool gateway. The request is
 * the scenario's own request, unchanged: no scenario ID, intent or label is ever sent, and the correlation ID is the API
 * client's usual random one (the approval scenario sends its analysis and its tool call in one trace of its own).
 */
export async function runScenario(scenario: AttackScenario, signal?: AbortSignal): Promise<ScenarioRun> {
  switch (scenario.kind) {
    case 'input':
      return { kind: 'input', scenarioId: scenario.id, result: await analyzeInput({ input: scenario.input }, signal) }
    case 'tool':
      return { kind: 'tool', scenarioId: scenario.id, result: await executeToolTraced(scenario.request, signal) }
    case 'replay':
      return runReplay(scenario, signal)
    case 'approval':
      return holdForApproval(scenario, signal)
  }
}

async function runReplay(scenario: ReplayScenario, signal: AbortSignal | undefined): Promise<ScenarioRun> {
  const first = await executeToolTraced(scenario.request, signal)
  const second = await presentExecutionId(scenario.request, first.execution.executionId, signal)
  return { kind: 'replay', scenarioId: scenario.id, first, second }
}

/**
 * The replay attempt: the same call, carrying the first response's execution ID as if it authorised the execution. The
 * contract has no such field, so the API is expected to reject it (400) before anything is decided or executed. This is
 * the only request the console sends outside the contract, deliberately.
 */
async function presentExecutionId(request: ToolExecutionRequest, executionId: string | null, signal: AbortSignal | undefined): Promise<ReplayAttempt> {
  try {
    const { data, meta } = await apiClient.postForEnvelope<ToolExecutionResult['execution']>(
      '/api/v1/agent/tools/execute',
      { ...request, executionId },
      { signal },
    )
    return { status: 'accepted', result: { execution: data, correlationId: meta.correlationId, timestamp: meta.timestamp } }
  } catch (error) {
    if (isApiError(error) && error.kind === 'http' && error.status === 400) {
      return { status: 'rejected', httpStatus: 400, contractRejection: error.errorCode === 'Request.Malformed', correlationId: error.correlationId }
    }

    return { status: 'failed', error }
  }
}

/** A fresh trace of the console's own: the analysis and the tool call that references it must share one. */
function newTrace(): string {
  return `lab-${crypto.randomUUID()}`
}

/**
 * Phase one: the firewall analyses the input; the tool call references that analysis (and claims the input was allowed),
 * in the same trace. The gateway decides from its own record of the analysis.
 */
async function holdForApproval(scenario: ApprovalScenario, signal: AbortSignal | undefined): Promise<ApprovalRun> {
  const trace = newTrace()
  const analysis = await analyzeInput({ input: scenario.input }, signal, trace)
  const held = await executeToolTraced({ ...scenario.request, inputEventId: analysis.analysis.securityEventId }, signal, trace)
  return { kind: 'approval', scenarioId: scenario.id, analysis, held }
}

const approvalStatuses: Readonly<Record<string, ApprovalDecision['answer']>> = { Approved: 'Approved', Denied: 'Denied' }

const conflicts: Readonly<Record<string, ApprovalDecision['answer']>> = {
  'Approval.Expired': 'Expired',
  'Approval.AlreadyDecided': 'AlreadyDecided',
  'Approval.NotFound': 'NotFound',
}

/**
 * Phase two: a person approves or denies the held call; then the agent presents the approval with the same call, so the
 * gateway (not the console) says whether anything ran. A decision the API refused (expired, already decided) is shown as
 * such; any other failure is raised.
 */
export async function decideApprovalRun(scenario: ApprovalScenario, run: ApprovalRun, approve: boolean, signal?: AbortSignal): Promise<ApprovalRun> {
  const approvalId = run.held.execution.approvalId
  if (typeof approvalId !== 'string' || approvalId === '') {
    throw new Error('The gateway created no approval for this call.')
  }

  let decision: ApprovalDecision
  try {
    const approval = await decideApproval(approvalId, approve, signal)
    const answer = Object.hasOwn(approvalStatuses, approval.status) ? approvalStatuses[approval.status] : undefined
    decision = { action: approve ? 'approve' : 'deny', answer: answer ?? 'Unrecognised', correlationId: undefined }
  } catch (error) {
    const code = isApiError(error) && error.kind === 'http' ? error.errorCode : undefined
    const conflict = code !== undefined && Object.hasOwn(conflicts, code) ? conflicts[code] : undefined
    if (conflict === undefined || !isApiError(error)) {
      throw error
    }

    decision = { action: approve ? 'approve' : 'deny', answer: conflict, correlationId: error.correlationId }
  }

  const final = await executeToolTraced({ ...scenario.request, approvalId }, signal)
  return { ...run, decision, final }
}
