/** Metadata attached to every successful envelope response. */
export interface ApiResponseMeta {
  correlationId: string
  timestamp: string
}

/** Successful response body under /api: `{ data, meta }`. Failures are never enveloped. */
export interface ApiEnvelope<T> {
  data: T
  meta: ApiResponseMeta
}

/** RFC 9457 Problem Details as produced by the AgentShield API. */
export interface ProblemDetails {
  type?: string
  title?: string
  status?: number
  detail?: string
  instance?: string
  correlationId?: string
  errorCode?: string
  timestamp?: string
  /** Validation: field path → messages. Other failures: list of additional errors. */
  errors?: Record<string, string[]> | { code: string; message: string }[]
}
