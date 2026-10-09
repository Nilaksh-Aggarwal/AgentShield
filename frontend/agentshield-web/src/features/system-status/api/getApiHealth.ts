import { apiClient } from '@/services/api'

export type HealthStatus = 'Healthy' | 'Degraded' | 'Unhealthy'

export interface HealthReport {
  status: HealthStatus
  totalDurationMs: number
  checks: { name: string; status: HealthStatus; durationMs: number; description: string | null }[]
}

/** /health sits outside the /api envelope convention. */
export function getApiHealth(signal?: AbortSignal): Promise<HealthReport> {
  return apiClient.get<HealthReport>('/health', { signal, envelope: false, timeoutMs: 5_000 })
}
