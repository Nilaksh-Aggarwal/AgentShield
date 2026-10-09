import { useQuery } from '@tanstack/react-query'
import { getApiHealth } from '../api/getApiHealth'

export const apiHealthQueryKey = ['system-status', 'health'] as const

export function useApiHealth() {
  return useQuery({
    queryKey: apiHealthQueryKey,
    queryFn: ({ signal }) => getApiHealth(signal),
    refetchInterval: 30_000,
  })
}
