import type { RiskLevel, SecurityDecision, ThreatCategory, ThreatSeverity } from '@/features/firewall'
import { apiClient } from '@/services/api'

/**
 * What AI-assisted analysis contributed. Deliberately coarse: every way an expected AI analysis can fail is
 * `Incomplete`; the reason stays in the server's audit log.
 */
export type ActivityAiStatus = 'Disabled' | 'Completed' | 'NotNeeded' | 'Incomplete'

/** What an activity record is about: the analysis of one input, the authorization of one agent action, or one tool call
 * through the tool gateway. */
export type SecurityActivityKind = 'InputAnalysis' | 'AgentActionAuthorization' | 'ToolExecution'

/**
 * An agent action as the history keeps it. Names come only from AgentShield's own configuration: one the caller made up
 * is `null`. There are never tool arguments.
 */
export interface ActivityAgentAction {
  agentId: string | null
  tool: string | null
  action: string | null
  capability: string | null
  reason: string
}

/**
 * How the tool gateway handled one tool call. Never the arguments, the tool's result, or why arguments or a grant were
 * rejected (those stay in the server's audit log).
 */
export interface ActivityToolExecution {
  outcome: string
  /** Whether the tool was invoked. */
  executed: boolean
  /** The execution grant's audit ID, when one was issued; not a credential. */
  executionId: string | null
}

export interface ActivityFinding {
  code: string
  category: ThreatCategory
  severity: ThreatSeverity
}

/** One security event as the activity history returns it: metadata only, never the analysed text. */
export interface ActivityItem {
  securityEventId: string
  /** Request trace ID of the analysis (distinct from the security event ID). */
  correlationId: string
  /** When the decision was made (ISO 8601). */
  occurredAt: string
  kind: SecurityActivityKind
  decision: SecurityDecision
  /** `score` is `null` for an agent action: its risk is a classification, not a score. */
  risk: { level: RiskLevel; score: number | null }
  /** Duplicates fused; most severe first. Empty for an agent action. */
  findings: ActivityFinding[]
  /** `null` for an agent action. */
  aiAnalysis: ActivityAiStatus | null
  /** `null` (or absent, from an older API) for an input analysis. */
  agentAction?: ActivityAgentAction | null
  /** Only for a tool execution; `null` (or absent, from an older API) otherwise. */
  toolExecution?: ActivityToolExecution | null
}

export interface ActivityPage {
  /** Newest first. */
  items: ActivityItem[]
  /** 1-based. */
  page: number
  pageSize: number
  totalCount: number
  /** 0 when nothing matches. */
  totalPages: number
}

export type DecisionFilter = 'all' | SecurityDecision

export interface ActivityQuery {
  page: number
  decision: DecisionFilter
}

/** Records per page; the API accepts 1–100 and defaults to 25. */
export const ACTIVITY_PAGE_SIZE = 25

/** GET /api/v1/activity: one page of recent security events, newest first. Requires the `activity:read` permission. */
export function listActivity(query: ActivityQuery, signal?: AbortSignal): Promise<ActivityPage> {
  const params = new URLSearchParams({ page: String(query.page), pageSize: String(ACTIVITY_PAGE_SIZE) })
  if (query.decision !== 'all') {
    params.append('decision', query.decision)
  }

  return apiClient.get<ActivityPage>(`/api/v1/activity?${params.toString()}`, { signal })
}
