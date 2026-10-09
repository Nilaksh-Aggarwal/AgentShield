import { apiClient } from '@/services/api'

/**
 * Counts over the activity history as the API process holds it right now (most recent events only, in memory, every
 * client, emptied on restart), all from one snapshot. Counts only: no event, ID, name or content.
 */
export interface ActivitySummary {
  totalCount: number
  /** When the oldest event held was decided (ISO 8601); `null` when the history is empty. */
  oldestOccurredAt: string | null
  newestOccurredAt: string | null
  decisions: { allow: number; review: number; block: number }
  kinds: { inputAnalysis: number; agentActionAuthorization: number; toolExecution: number }
  /** Tool calls whose tool ran and returned a result. */
  toolsExecuted: number
}

/** GET /api/v1/activity/summary. Requires the `activity:read` permission. */
export function getActivitySummary(signal?: AbortSignal): Promise<ActivitySummary> {
  return apiClient.get<ActivitySummary>('/api/v1/activity/summary', { signal })
}
