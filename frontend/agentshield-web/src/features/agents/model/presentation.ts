import { isApiError } from '@/services/api'
import type { Tone } from '@/shared/components/ui'

// Own-property lookups only (D-17): an API value such as "constructor" must not select an inherited member.
function own<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined
}

export interface ActionDecisionPresentation {
  label: string
  /** What the caller may do with the action. */
  action: string
  tone: Tone
  known: boolean
}

const decisions: Readonly<Record<string, Omit<ActionDecisionPresentation, 'known'>>> = {
  Allow: { label: 'Allow', action: 'May run', tone: 'success' },
  Review: { label: 'Review', action: 'Needs a person’s approval', tone: 'warning' },
  Block: { label: 'Block', action: 'Must not run', tone: 'danger' },
}

/**
 * An authorization decision on an agent action. Only Allow permits running it, so a decision this console does not know is
 * never shown as one: it is shown as not runnable, and its value is not echoed.
 */
export function presentActionDecision(decision: unknown): ActionDecisionPresentation {
  const entry = own(decisions, decision)
  return entry ? { ...entry, known: true } : { label: 'Unknown', action: 'Do not run: decision not recognised', tone: 'warning', known: false }
}

export interface ReasonPresentation {
  /** A few words, for tables. */
  label: string
  /** One sentence for readers who do not know the policy. */
  explanation: string
}

const reasons: Readonly<Record<string, ReasonPresentation>> = {
  Permitted: { label: 'Permitted', explanation: 'The agent holds the capability this action requires, and the action is low or medium risk.' },
  HumanApprovalRequired: { label: 'Needs approval', explanation: 'A high-risk action: a person must approve it before it runs.' },
  InputHeldForReview: { label: 'Input under review', explanation: 'The input behind this action is held for review, so the action is too.' },
  UnknownAgent: { label: 'Unknown agent', explanation: 'This agent is not configured in AgentShield.' },
  UnknownTool: { label: 'Unknown tool', explanation: 'This tool is not in AgentShield’s tool catalogue.' },
  UnknownAction: { label: 'Unknown action', explanation: 'This action of the tool is not in the catalogue.' },
  CapabilityMismatch: { label: 'Wrong capability', explanation: 'The capability the agent claimed is not the one this action requires.' },
  CapabilityNotGranted: { label: 'Capability not granted', explanation: 'The agent was not granted the capability this action requires.' },
  CriticalActionDenied: { label: 'Critical action', explanation: 'A critical action (money, credentials, deletion, permissions): no agent may run it on its own authority.' },
  InputBlocked: { label: 'Input blocked', explanation: 'The input behind this action was blocked, so the action is too.' },
  CallerNotBoundToAgent: { label: 'Client not bound', explanation: 'This client is not allowed to act for this agent.' },
}

/** Why the boundary decided. A reason this console does not know is not echoed. */
export function presentAgentActionReason(reason: unknown): ReasonPresentation {
  return own(reasons, reason) ?? { label: 'Not recognised', explanation: 'AgentShield gave a reason this console does not recognise.' }
}

export interface AgentSecurityErrorPresentation {
  title: string
  description: string
  reference?: string
}

/** A failed preview run in plain language. Uses only the status, the client's own error kind and `Retry-After`. */
export function presentAgentSecurityError(error: unknown): AgentSecurityErrorPresentation {
  if (!isApiError(error)) {
    return { title: 'The preview couldn’t run', description: 'Something unexpected went wrong. Try again.' }
  }

  const reference = error.correlationId
  switch (error.kind) {
    case 'network':
      return { title: 'Can’t reach the AgentShield API', description: 'Check that the API is running, then try again.', reference }
    case 'timeout':
      return { title: 'The preview took too long', description: 'No answer arrived in time. Try again.', reference }
    case 'aborted':
      return { title: 'The preview was cancelled', description: 'Try again.', reference }
    case 'invalid-response':
      return { title: 'Unexpected response from the API', description: 'The API answered in a form this console does not understand.', reference }
    case 'http':
      return { ...presentHttpError(error.status ?? 0, error.retryAfterSeconds), reference }
  }
}

function presentHttpError(status: number, retryAfterSeconds: number | undefined): Omit<AgentSecurityErrorPresentation, 'reference'> {
  switch (status) {
    case 401:
      return { title: 'Authentication required', description: 'The API did not accept this console’s credentials.' }
    case 403:
      return {
        title: 'You don’t have permission to request agent authorizations',
        description: 'This client is signed in but not allowed to ask the agent authorization boundary for decisions.',
      }
    case 400:
    case 422:
      return { title: 'An example was not accepted', description: 'The API rejected one of the example requests.' }
    case 429:
      return {
        title: 'Temporarily rate limited',
        description:
          retryAfterSeconds === undefined
            ? 'Too many requests in a short time. Wait a moment, then try again.'
            : `Too many requests in a short time. Try again in ${retryAfterSeconds} ${retryAfterSeconds === 1 ? 'second' : 'seconds'}.`,
      }
    default:
      return status >= 500
        ? { title: 'No decision was made', description: 'The server could not decide or record a decision. If it keeps happening, quote the reference below.' }
        : { title: 'The request could not be processed', description: 'The API refused the request.' }
  }
}
