import { isApiError } from '@/services/api'
import type { Tone } from '@/shared/components/ui'
import type { ToolExecution, ToolExecutionRequest } from '../api/executeTool'
import { presentAgentSecurityError, type AgentSecurityErrorPresentation } from './presentation'

// Own-property lookups only (D-17): an API value such as "constructor" must not select an inherited member.
function own<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined
}

export interface ToolOutcomePresentation {
  /** A few words, for tables. */
  label: string
  /** One sentence for readers who do not know the gateway. */
  explanation: string
  tone: Tone
}

const outcomes: Readonly<Record<string, ToolOutcomePresentation>> = {
  Executed: { label: 'Tool ran', explanation: 'The gateway issued a single-use grant for this call, checked it, and ran the tool once.', tone: 'success' },
  HeldForReview: { label: 'Held for review', explanation: 'A person must approve this action first, so the tool did not run.', tone: 'warning' },
  Denied: { label: 'Blocked', explanation: 'The authorization boundary blocked the action, so the tool did not run.', tone: 'danger' },
  ArgumentsRejected: { label: 'Arguments rejected', explanation: 'The arguments do not match the tool’s schema, so the tool did not run.', tone: 'danger' },
  ToolUnavailable: { label: 'No tool to run', explanation: 'The action was allowed, but the gateway has no tool that executes it. Nothing ran.', tone: 'danger' },
  ExecutionAuthorizationRejected: { label: 'Grant refused', explanation: 'The execution grant was not valid for this call, so the tool did not run.', tone: 'danger' },
  ExecutionFailed: { label: 'Tool failed', explanation: 'The tool was started but failed; no result was returned.', tone: 'danger' },
  InputContextRejected: {
    label: 'Input event rejected',
    explanation: 'The input analysis this call referenced could not be verified (unknown, expired, another client’s or another trace’s), so nothing ran.',
    tone: 'danger',
  },
  ApprovalRejected: {
    label: 'Approval rejected',
    explanation: 'The approval presented is not an approved, unused, unexpired approval of exactly this call, so nothing ran.',
    tone: 'danger',
  },
}

/** How the gateway handled a request. An outcome this console does not know is not echoed. */
export function presentToolOutcome(outcome: unknown): ToolOutcomePresentation {
  return own(outcomes, outcome) ?? { label: 'Not recognised', explanation: 'AgentShield reported an outcome this console does not recognise.', tone: 'warning' }
}

/**
 * Whether the tool ran, by everything the API said about it: an Allow, `executed`, and the `Executed` outcome. Anything less
 * (an unknown decision or outcome, or fields that disagree) is shown as not run, and its result is never shown.
 */
export function toolRan(execution: Pick<ToolExecution, 'decision' | 'executed' | 'outcome'>): boolean {
  return execution.decision === 'Allow' && execution.executed === true && execution.outcome === 'Executed'
}

/** The tool's result text, only for a tool that ran and found something. */
export function resultText(execution: ToolExecution): string | undefined {
  const { result } = execution
  return toolRan(execution) && result?.found === true && typeof result.text === 'string' ? result.text : undefined
}

/** A failed gateway preview in plain language: the authorization preview's wording, except where the gateway differs. */
export function presentToolGatewayError(error: unknown): AgentSecurityErrorPresentation {
  if (isApiError(error) && error.kind === 'http') {
    const reference = error.correlationId
    if (error.status === 403) {
      return { title: 'You don’t have permission to execute tools', description: 'This client is signed in but not allowed to use the tool gateway.', reference }
    }

    if ((error.status ?? 0) >= 500) {
      return {
        title: 'No result was returned',
        description: 'The gateway could not decide, record or complete a request. If it keeps happening, quote the reference below.',
        reference,
      }
    }
  }

  return presentAgentSecurityError(error)
}

/** The arguments of an example as compact JSON, shortened for display (the request itself is sent unshortened). */
export function describeArguments(request: ToolExecutionRequest, maxLength = 60): string {
  const text = JSON.stringify(request.arguments)
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 1)}…`
}
