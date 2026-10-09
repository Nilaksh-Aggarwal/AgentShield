import { describe, expect, it, vi } from 'vitest'
import { apiClient, CORRELATION_HEADER } from './apiClient'
import { ApiError } from './apiError'

function respondWith(response: Response) {
  const fetchMock = vi.fn<(url: string, init: RequestInit) => Promise<Response>>(() => Promise.resolve(response))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  const error: unknown = await promise.then(
    () => undefined,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(ApiError)
  return error as ApiError
}

describe('apiClient.postForEnvelope', () => {
  it('returns the envelope and sends JSON with a correlation ID', async () => {
    const fetchMock = respondWith(json(200, { data: { decision: 'Block' }, meta: { correlationId: 'c-1', timestamp: '2026-10-01T00:00:00Z' } }))

    const envelope = await apiClient.postForEnvelope<{ decision: string }>('/api/v1/firewall/analyze', { input: 'x' })

    expect(envelope.data.decision).toBe('Block')
    const [url, init] = fetchMock.mock.calls[0]!
    const headers = new Headers(init.headers)
    expect(url).toBe('/api/v1/firewall/analyze')
    expect(init.body).toBe('{"input":"x"}')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get(CORRELATION_HEADER)).toMatch(/^[0-9a-f]{32}$/)
  })

  it('turns Problem Details into an ApiError with status, code, correlation ID, field errors and Retry-After', async () => {
    respondWith(json(429, { title: 'Too many requests', errorCode: 'RateLimit.Exceeded', correlationId: 'c-429', errors: { input: ['Too long.'] } }, { 'Retry-After': '30' }))

    const error = await failure(apiClient.postForEnvelope('/api/v1/firewall/analyze', { input: 'x' }))

    expect(error).toMatchObject({ kind: 'http', status: 429, errorCode: 'RateLimit.Exceeded', correlationId: 'c-429', retryAfterSeconds: 30 })
    expect(error.fieldErrors).toEqual({ input: ['Too long.'] })
  })

  it('ignores a malformed Retry-After instead of inventing a wait', async () => {
    respondWith(json(429, { title: 'Too many requests' }, { 'Retry-After': '-5' }))

    expect((await failure(apiClient.postForEnvelope('/x', {}))).retryAfterSeconds).toBeUndefined()
  })

  it('keeps the response correlation ID for an error without a JSON body', async () => {
    respondWith(new Response('<html>Bad gateway</html>', { status: 502, headers: { 'Content-Type': 'text/html', [CORRELATION_HEADER]: 'c-502' } }))

    const error = await failure(apiClient.postForEnvelope('/x', {}))

    expect(error).toMatchObject({ kind: 'http', status: 502, correlationId: 'c-502', problem: undefined, isTransient: true })
    expect(error.userMessage).not.toContain('html')
  })

  it.each([
    ['a body that is not JSON', new Response('not json', { status: 200 })],
    ['JSON without the envelope', json(200, { decision: 'Allow' })],
    ['an envelope without meta', json(200, { data: { decision: 'Allow' } })],
  ])('rejects %s as an invalid response, never as a decision', async (_name, response) => {
    respondWith(response)

    expect((await failure(apiClient.postForEnvelope('/x', {}))).kind).toBe('invalid-response')
  })

  it('reports a network failure', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))))

    expect((await failure(apiClient.postForEnvelope('/x', {}))).kind).toBe('network')
  })

  it('reports a cancellation by the caller', async () => {
    const controller = new AbortController()
    vi.stubGlobal('fetch', vi.fn((_url: string, init: RequestInit) => {
      controller.abort()
      return Promise.reject(new DOMException(init.signal?.aborted ? 'Aborted' : 'Not aborted', 'AbortError'))
    }))

    expect((await failure(apiClient.postForEnvelope('/x', {}, { signal: controller.signal }))).kind).toBe('aborted')
  })

  it('reports a timeout', async () => {
    vi.stubGlobal('fetch', vi.fn((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('Timed out', 'TimeoutError')))),
    ))

    expect((await failure(apiClient.postForEnvelope('/x', {}, { timeoutMs: 10 }))).kind).toBe('timeout')
  })

  it('never exposes server text in the user message of a server error', async () => {
    respondWith(json(500, { title: 'An unexpected error occurred.', detail: 'NullReferenceException at Secret.Method' }))

    expect((await failure(apiClient.postForEnvelope('/x', {}))).userMessage).toBe('The server could not complete the request. Please try again later.')
  })
})
