import { useQuery } from '@tanstack/react-query'
import { getActivitySummary } from '../api/getActivitySummary'

/**
 * Counts over the activity history. Read-only, so a cached query, but never treated as fresh: every analysis, decision and
 * tool call changes it, so it refetches whenever it is shown.
 */
export function useActivitySummary() {
  return useQuery({
    queryKey: ['activity', 'summary'],
    queryFn: ({ signal }) => getActivitySummary(signal),
    staleTime: 0,
  })
}
