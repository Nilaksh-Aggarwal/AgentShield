import { QueryClient } from '@tanstack/react-query'
import { isApiError } from '@/services/api'

const MAX_QUERY_RETRIES = 2

/**
 * Server-state cache. Queries retry only transient failures (network, timeout, 502/503/504) — never
 * 4xx. Mutations never retry automatically: they may be non-idempotent (mirrors the backend rule).
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => isApiError(error) && error.isTransient && failureCount < MAX_QUERY_RETRIES,
      },
      mutations: {
        retry: false,
      },
    },
  })
}
