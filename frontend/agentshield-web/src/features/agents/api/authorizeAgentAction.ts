import type { RiskLevel, SecurityDecision } from '@/features/firewall'
import { apiClient } from '@/services/api'

/** Why the authorization boundary decided as it did (coarse, stable codes; never rule IDs). */
export type AgentActionReason =
  | 'Permitted'
  | 'HumanApprovalRequired'
  | 'InputHeldForReview'
  | 'UnknownAgent'
  | 'UnknownTool'
  | 'UnknownAction'
  | 'CapabilityMismatch'
  | 'CapabilityNotGranted'
  | 'CriticalActionDenied'
  | 'InputBlocked'
  | 'CallerNotBoundToAgent'

/** An agent's proposed tool action. Names are exact lower-case identifiers; there is no field for tool arguments. */
export interface AgentActionRequest {
  agentId: string
  tool: string
  action: string
  /** The capability the agent claims authorises the action, `resource:operation`. */
  capability: string
  /** The firewall's decision on the input behind the action; it can only make the decision stricter. */
  inputDecision?: SecurityDecision
}

/** The boundary's decision. Only `Allow` permits running the action; nothing was executed either way. */
export interface AgentActionAuthorization {
  securityEventId: string
  decision: SecurityDecision
  /** Risk of the action itself; `Critical` when the action is unknown. No score. */
  riskLevel: RiskLevel
  reason: AgentActionReason
}

/**
 * POST /api/v1/agent/actions/authorize: asks whether an agent may perform a tool action. Any decision (Block included) is a
 * 200 response, and each one is recorded as a security event. Requires the `agent:authorize` permission.
 */
export function authorizeAgentAction(request: AgentActionRequest, signal?: AbortSignal): Promise<AgentActionAuthorization> {
  return apiClient.post<AgentActionAuthorization>('/api/v1/agent/actions/authorize', request, { signal })
}
