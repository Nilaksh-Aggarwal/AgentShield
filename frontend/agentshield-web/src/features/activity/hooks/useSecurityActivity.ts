import { useQuery } from '@tanstack/react-query'
import { listActivity, type ActivityQuery } from '../api/listActivity'

/**
 * One page of the activity history. Read-only, so it is a cached query (transient failures retry, others do not), but
 * never treated as fresh: every analysis adds to the history, so it refetches whenever the page is shown. While paging
 * within one filter the previous page stays on screen until the next arrives; a new filter never shows another
 * filter's rows.
 */
export function useSecurityActivity(query: ActivityQuery) {
  return useQuery({
    queryKey: ['activity', query.decision, query.page],
    queryFn: ({ signal }) => listActivity(query, signal),
    staleTime: 0,
    placeholderData: (previous, previousQuery) => (previousQuery?.queryKey[1] === query.decision ? previous : undefined),
  })
}
