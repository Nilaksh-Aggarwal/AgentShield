import { isApiError } from '@/services/api'
import { StatusIndicator, type StatusTone } from '@/shared/components/ui'
import { useApiHealth } from '../hooks/useApiHealth'

/** Live reachability of the API (`/health`), refreshed every 30 seconds. Says nothing about AI analysis. */
export function ApiHealthIndicator() {
  const { data, error, isPending } = useApiHealth()

  let tone: StatusTone = 'pending'
  let label = 'Checking API…'
  let title: string | undefined

  if (data) {
    tone = data.status === 'Healthy' ? 'ok' : data.status === 'Degraded' ? 'warning' : 'down'
    label = `API ${data.status.toLowerCase()}`
  } else if (!isPending && error) {
    tone = 'down'
    label = 'API unavailable'
    title = isApiError(error) ? error.userMessage : undefined
  }

  return <StatusIndicator tone={tone} label={label} role="status" title={title} />
}
