import { isApiError } from '@/services/api'
import type { Tone } from '@/shared/components/ui'
import { presentAgentSecurityError, type AgentSecurityErrorPresentation } from './presentation'

// Own-property lookups only (D-17): an API value such as "constructor" must not select an inherited member.
function own<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined
}

export interface ApprovalStatusPresentation {
  label: string
  /** What the status means for the held call, in one sentence. */
  explanation: string
  tone: Tone
  /** Only a pending approval can be approved or denied. */
  pending: boolean
}

const statuses: Readonly<Record<string, ApprovalStatusPresentation>> = {
  Pending: { label: 'Pending approval', explanation: 'Nothing runs until a person decides.', tone: 'warning', pending: true },
  Approved: {
    label: 'Approved',
    explanation: 'The agent may run exactly this call once, before the approval expires.',
    tone: 'info',
    pending: false,
  },
  Used: {
    label: 'Approved and used',
    explanation: 'The agent presented the approval with the call once; it can never authorise anything again.',
    tone: 'success',
    pending: false,
  },
  Denied: { label: 'Denied', explanation: 'Tool not executed: this call never runs with this approval.', tone: 'danger', pending: false },
  Expired: {
    label: 'Expired',
    explanation: 'Tool not executed: nobody decided, or the approved call was not run, in time.',
    tone: 'neutral',
    pending: false,
  },
}

/** An approval's status. One this console does not know is never echoed and never shown as approved. */
export function presentApprovalStatus(status: unknown): ApprovalStatusPresentation {
  return (
    own(statuses, status) ?? {
      label: 'Not recognised',
      explanation: 'AgentShield reported a status this console does not recognise; treat the call as not approved.',
      tone: 'warning',
      pending: false,
    }
  )
}

/** A failed approval request in plain language. Uses only the status and the API's stable error code, never its text. */
export function presentApprovalError(error: unknown): AgentSecurityErrorPresentation {
  if (isApiError(error) && error.kind === 'http') {
    const reference = error.correlationId
    switch (error.status) {
      case 403:
        return {
          title: 'You don’t have permission to approve tool calls',
          description: 'This client is signed in but does not hold the approval permission. Nothing was decided.',
          reference,
        }
      case 404:
        return { title: 'No such approval', description: 'AgentShield holds no approval with this ID. Nothing was decided.', reference }
      case 409:
        return error.errorCode === 'Approval.Expired'
          ? { title: 'The approval expired', description: 'It was not decided in time, so the held call will never run.', reference }
          : { title: 'Already decided', description: 'An approval is decided once; this one was decided or used already.', reference }
    }

    if (error.status !== undefined && error.status >= 500) {
      return {
        title: 'AgentShield couldn’t complete the approval request',
        description: 'Nothing was approved or denied. If it keeps happening, quote the reference below.',
        reference,
      }
    }
  }

  return presentAgentSecurityError(error)
}
