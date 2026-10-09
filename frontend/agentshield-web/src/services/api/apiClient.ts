import { apiConfig } from '@/shared/constants/config'
import { ApiError } from './apiError'
import { parseRetryAfter } from './retryAfter'
import type { ApiEnvelope, ProblemDetails } from './types'

/**
 * Central HTTP client. Every backend call goes through here (ESLint forbids `fetch` elsewhere), so
 * base URL, JSON, correlation IDs, auth headers, timeouts, cancellation and error normalisation are
 * handled in exactly one place.
 */

export const CORRELATION_HEADER = 'X-Correlation-ID'

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export interface RequestOptions {
  /** Cancellation from the caller (TanStack Query passes one to every query function). */
  signal?: AbortSignal
  /** Overrides the default client-side timeout. */
  timeoutMs?: number
  headers?: Record<string, string>
  /**
   * `true` (default) for /api endpoints, which wrap data in `{ data, meta }`.
   * `false` for endpoints outside the envelope convention (e.g. /health).
   */
  envelope?: boolean
}

type AccessTokenProvider = () => string | null | undefined | Promise<string | null | undefined>

let accessTokenProvider: AccessTokenProvider | undefined

/** Authentication hook-up point: once auth exists, register a provider and every request carries a bearer token. */
export function setAccessTokenProvider(provider: AccessTokenProvider | undefined): void {
  accessTokenProvider = provider
}

export const apiClient = {
  get: <T>(path: string, options?: RequestOptions) => request<T>('GET', path, undefined, options),
  post: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>('POST', path, body, options),
  put: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>('PUT', path, body, options),
  patch: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>('PATCH', path, body, options),
  delete: <T = void>(path: string, options?: RequestOptions) => request<T>('DELETE', path, undefined, options),
  /** POST that returns the whole `{ data, meta }` envelope, for callers that show response metadata (correlation ID). */
  postForEnvelope: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'envelope'>) =>
    requestEnvelope<T>('POST', path, body, options),
}

async function request<T>(method: HttpMethod, path: string, body: unknown, options: RequestOptions = {}): Promise<T> {
  const { payload, status, correlationId } = await send(method, path, body, options)

  if (status === 204 || options.envelope === false) {
    return payload as T
  }

  if (!isEnvelope<T>(payload)) {
    throw new ApiError({ kind: 'invalid-response', status, correlationId })
  }

  return payload.data
}

async function requestEnvelope<T>(
  method: HttpMethod,
  path: string,
  body: unknown,
  options: RequestOptions = {},
): Promise<ApiEnvelope<T>> {
  const { payload, status, correlationId } = await send(method, path, body, options)

  if (!isEnvelope<T>(payload)) {
    throw new ApiError({ kind: 'invalid-response', status, correlationId })
  }

  return payload
}

interface SentRequest {
  payload: unknown
  status: number
  correlationId: string
}

/** Performs the request and turns every failure into an `ApiError`; returns the parsed body of a success. */
async function send(method: HttpMethod, path: string, body: unknown, options: RequestOptions): Promise<SentRequest> {
  const correlationId = createCorrelationId()
  const headers = new Headers({ Accept: 'application/json', [CORRELATION_HEADER]: correlationId, ...options.headers })

  if (body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }

  const token = await accessTokenProvider?.()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const timeoutSignal = AbortSignal.timeout(options.timeoutMs ?? apiConfig.timeoutMs)
  const signal = options.signal ? AbortSignal.any([options.signal, timeoutSignal]) : timeoutSignal

  let response: Response
  try {
    response = await fetch(buildUrl(path), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: 'same-origin',
    })
  } catch (error) {
    if (timeoutSignal.aborted) {
      throw new ApiError({ kind: 'timeout', correlationId, cause: error })
    }
    if (options.signal?.aborted) {
      throw new ApiError({ kind: 'aborted', correlationId, cause: error })
    }
    throw new ApiError({ kind: 'network', correlationId, cause: error })
  }

  const responseCorrelationId = response.headers.get(CORRELATION_HEADER) ?? correlationId

  if (!response.ok) {
    throw new ApiError({
      kind: 'http',
      status: response.status,
      problem: await readProblem(response),
      correlationId: responseCorrelationId,
      retryAfterSeconds: parseRetryAfter(response.headers.get('Retry-After')),
    })
  }

  if (response.status === 204) {
    return { payload: undefined, status: response.status, correlationId: responseCorrelationId }
  }

  try {
    return { payload: await response.json(), status: response.status, correlationId: responseCorrelationId }
  } catch (error) {
    throw new ApiError({ kind: 'invalid-response', status: response.status, correlationId: responseCorrelationId, cause: error })
  }
}

function buildUrl(path: string): string {
  const base = apiConfig.baseUrl.replace(/\/+$/, '')
  return `${base}${path.startsWith('/') ? path : `/${path}`}`
}

function createCorrelationId(): string {
  return crypto.randomUUID().replaceAll('-', '')
}

async function readProblem(response: Response): Promise<ProblemDetails | undefined> {
  const contentType = response.headers.get('Content-Type') ?? ''
  if (!contentType.includes('json')) {
    return undefined
  }

  try {
    return toProblemDetails(await response.json())
  } catch {
    return undefined
  }
}

/** Copies only well-typed Problem Details members; anything else in an error body is ignored. */
function toProblemDetails(body: unknown): ProblemDetails | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return undefined
  }

  const source = body as Record<string, unknown>
  const text = (key: string) => (typeof source[key] === 'string' ? source[key] : undefined)

  return {
    type: text('type'),
    title: text('title'),
    status: typeof source.status === 'number' ? source.status : undefined,
    detail: text('detail'),
    instance: text('instance'),
    correlationId: text('correlationId'),
    errorCode: text('errorCode'),
    timestamp: text('timestamp'),
    errors: toErrors(source.errors),
  }
}

function toErrors(value: unknown): ProblemDetails['errors'] {
  if (Array.isArray(value)) {
    return value.filter(
      (item): item is { code: string; message: string } =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as Record<string, unknown>).code === 'string' &&
        typeof (item as Record<string, unknown>).message === 'string',
    )
  }

  if (typeof value === 'object' && value !== null) {
    const fieldErrors: Record<string, string[]> = {}
    for (const [field, messages] of Object.entries(value)) {
      if (Array.isArray(messages)) {
        fieldErrors[field] = messages.filter((message): message is string => typeof message === 'string')
      }
    }
    return fieldErrors
  }

  return undefined
}

function isEnvelope<T>(payload: unknown): payload is ApiEnvelope<T> {
  return typeof payload === 'object' && payload !== null && 'data' in payload && 'meta' in payload
}
