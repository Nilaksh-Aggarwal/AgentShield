import { presentFinding } from '@/features/firewall'
import { isApiError } from '@/services/api'
import type { Tone } from '@/shared/components/ui'
import type { ActivityFinding, DecisionFilter } from '../api/listActivity'

export interface AiStatusPresentation {
  label: string
  tone: Tone
}

// Own-property lookups only (D-17): an API value such as "constructor" must not select an inherited member.
function own<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined
}

const aiStatuses: Readonly<Record<string, AiStatusPresentation>> = {
  Disabled: { label: 'Not enabled', tone: 'neutral' },
  Completed: { label: 'Completed', tone: 'info' },
  NotNeeded: { label: 'Not needed', tone: 'neutral' },
  Incomplete: { label: 'Incomplete', tone: 'warning' },
}

/**
 * What AI-assisted analysis contributed to an event. A value this console does not know is never echoed: it could be a
 * failure reason (timeout, capacity, open circuit) that the history deliberately does not reveal.
 */
export function presentAiStatus(status: unknown): AiStatusPresentation {
  return own(aiStatuses, status) ?? { label: 'Not reported', tone: 'neutral' }
}

export interface ActivityKindPresentation {
  /** A word or two: what the record is about. */
  label: string
  /** True for agent actions and tool calls, false for input analyses and unknown kinds. */
  agent: boolean
}

const kinds: Readonly<Record<string, ActivityKindPresentation>> = {
  InputAnalysis: { label: 'Input', agent: false },
  AgentActionAuthorization: { label: 'Agent action', agent: true },
  ToolExecution: { label: 'Tool call', agent: true },
}

/** What a record is about. A kind this console does not know is not echoed. */
export function presentActivityKind(kind: unknown): ActivityKindPresentation {
  return own(kinds, kind) ?? { label: 'Unknown kind', agent: false }
}

export interface FindingSummary {
  /** Plain-language title of the most severe finding; `undefined` when there is none. */
  primary: string | undefined
  /** How many other distinct findings there are. */
  more: number
}

/** The findings behind a decision in one line: the API sends them most severe first, so the first one leads. */
export function summariseFindings(findings: readonly ActivityFinding[]): FindingSummary {
  // The history has no confidence or description: the catalogue supplies titles, and nothing else is shown.
  const titles = [...new Set(findings.map((finding) => presentFinding({ ...finding, confidence: Number.NaN, description: '' }).title))]
  return { primary: titles[0], more: Math.max(0, titles.length - 1) }
}

export interface FilterOption {
  value: DecisionFilter
  label: string
}

export const decisionFilters: readonly FilterOption[] = [
  { value: 'all', label: 'All' },
  { value: 'Allow', label: 'Allowed' },
  { value: 'Review', label: 'Review' },
  { value: 'Block', label: 'Blocked' },
]

/** `occurredAt` as a valid date, or `undefined` for anything that is not one. */
export function parseOccurredAt(value: unknown): Date | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date
}

export interface ActivityErrorPresentation {
  title: string
  description: string
  /** Correlation ID of the failed request, for support. */
  reference?: string
}

/**
 * A failed read of the history in plain language. Uses only the status, the client's own error kind and `Retry-After`;
 * server text is never shown.
 */
export function presentActivityError(error: unknown): ActivityErrorPresentation {
  if (!isApiError(error)) {
    return { title: 'Activity couldn’t be loaded', description: 'Something unexpected went wrong. Try again.' }
  }

  const reference = error.correlationId
  switch (error.kind) {
    case 'network':
      return { title: 'Can’t reach the AgentShield API', description: 'Check that the API is running, then try again.', reference }
    case 'timeout':
      return { title: 'Loading activity took too long', description: 'No answer arrived in time. Try again.', reference }
    case 'aborted':
      return { title: 'Loading activity was cancelled', description: 'Try again.', reference }
    case 'invalid-response':
      return {
        title: 'Unexpected response from the API',
        description: 'The API answered in a form this console does not understand.',
        reference,
      }
    case 'http':
      return { ...presentHttpError(error.status ?? 0, error.retryAfterSeconds), reference }
  }
}

function presentHttpError(status: number, retryAfterSeconds: number | undefined): Omit<ActivityErrorPresentation, 'reference'> {
  switch (status) {
    case 401:
      return { title: 'Authentication required', description: 'The API did not accept this console’s credentials.' }
    case 403:
      return {
        title: 'You don’t have permission to view activity',
        description: 'This client is signed in but not allowed to read the security activity history.',
      }
    case 422:
    case 400:
      return { title: 'The activity request was not accepted', description: 'Reload the page and try again.' }
    case 429:
      return {
        title: 'Activity temporarily rate limited',
        description:
          retryAfterSeconds === undefined
            ? 'Too many requests in a short time. Wait a moment, then try again.'
            : `Too many requests in a short time. Try again in ${retryAfterSeconds} ${retryAfterSeconds === 1 ? 'second' : 'seconds'}.`,
      }
    default:
      return status >= 500
        ? {
            title: 'Activity couldn’t be loaded',
            description: 'The server could not read the activity history. If it keeps happening, quote the reference below.',
          }
        : { title: 'The activity request could not be processed', description: 'The API refused the request.' }
  }
}
