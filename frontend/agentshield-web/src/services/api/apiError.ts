import type { ProblemDetails } from './types'

export type ApiErrorKind =
  /** The server answered with a 4xx/5xx status. */
  | 'http'
  /** The server could not be reached (offline, DNS, CORS, connection refused). */
  | 'network'
  /** The client-side timeout elapsed. */
  | 'timeout'
  /** The caller cancelled the request (e.g. component unmounted). */
  | 'aborted'
  /** The server answered successfully but the body was not what the contract promises. */
  | 'invalid-response'

interface ApiErrorInit {
  kind: ApiErrorKind
  status?: number
  problem?: ProblemDetails
  correlationId?: string
  /** From the response's `Retry-After` header (429, 503), when present. */
  retryAfterSeconds?: number
  cause?: unknown
}

/**
 * The only error type the API client throws. UI code renders `userMessage` — never raw
 * server text, exception messages or stack traces.
 */
export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status: number | undefined
  readonly errorCode: string | undefined
  readonly correlationId: string | undefined
  readonly problem: ProblemDetails | undefined
  /** Field-level validation messages keyed by camelCase property path (422 responses). */
  readonly fieldErrors: Readonly<Record<string, string[]>>
  /** Seconds the server asked the client to wait (`Retry-After`); `undefined` when it did not say. */
  readonly retryAfterSeconds: number | undefined

  constructor(init: ApiErrorInit) {
    super(describe(init), { cause: init.cause })
    this.name = 'ApiError'
    this.kind = init.kind
    this.status = init.status
    this.problem = init.problem
    this.errorCode = init.problem?.errorCode
    this.correlationId = init.problem?.correlationId ?? init.correlationId
    this.fieldErrors = extractFieldErrors(init.problem)
    this.retryAfterSeconds = init.retryAfterSeconds
  }

  /** Safe, human-readable message for display. */
  get userMessage(): string {
    switch (this.kind) {
      case 'network':
        return 'Unable to reach the AgentShield API. Check that the backend is running.'
      case 'timeout':
        return 'The request timed out. Please try again.'
      case 'aborted':
        return 'The request was cancelled.'
      case 'invalid-response':
        return 'The server returned an unexpected response.'
      case 'http':
        if (this.status !== undefined && this.status >= 500) {
          return 'The server could not complete the request. Please try again later.'
        }
        // 4xx details are written by the API for consumers and are safe to show.
        return this.problem?.detail ?? this.problem?.title ?? 'The request could not be processed.'
    }
  }

  /** Whether retrying the same request may succeed (used by the query client's retry policy). */
  get isTransient(): boolean {
    return (
      this.kind === 'network' ||
      this.kind === 'timeout' ||
      this.status === 502 ||
      this.status === 503 ||
      this.status === 504
    )
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}

function describe(init: ApiErrorInit): string {
  const status = init.status === undefined ? '' : ` ${init.status}`
  const code = init.problem?.errorCode ? ` (${init.problem.errorCode})` : ''
  return `API request failed: ${init.kind}${status}${code}`
}

function extractFieldErrors(problem: ProblemDetails | undefined): Record<string, string[]> {
  const errors = problem?.errors
  if (!errors || Array.isArray(errors)) {
    return {}
  }
  return errors
}
