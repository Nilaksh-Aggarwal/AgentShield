import type { RiskLevel, SecurityDecision } from '@/features/firewall'
import { apiClient } from '@/services/api'
import type { AgentActionReason } from './authorizeAgentAction'

/** Where a person's approval of a held tool call stands. */
export type ToolApprovalStatus = 'Pending' | 'Approved' | 'Denied' | 'Expired' | 'Used'

/**
 * A held tool call's approval, as the API returns it: metadata only (never the call's arguments). Approving runs nothing:
 * the agent presents the approval with the same call to the tool gateway, once.
 */
export interface ToolApproval {
  approvalId: string
  status: ToolApprovalStatus
  /** The security event of the gateway request that was held. */
  securityEventId: string
  correlationId: string
  agentId: string
  tool: string
  action: string
  capability: string
  riskLevel: RiskLevel
  reason: AgentActionReason
  /** The input decision the call was held under, when it had one. */
  inputDecision: SecurityDecision | null
  requestedAt: string
  expiresAt: string
  decidedAt: string | null
}

export interface ToolApprovalList {
  items: ToolApproval[]
}

/** GET /api/v1/agent/approvals: the most recent approvals, newest first. Requires the `agent:approve` permission. */
export function listApprovals(signal?: AbortSignal): Promise<ToolApprovalList> {
  return apiClient.get<ToolApprovalList>('/api/v1/agent/approvals', { signal })
}

/**
 * POST /api/v1/agent/approvals/{id}/approve or /deny. No body: the approval, the call it binds, its risk and reason all come
 * from the server's own state. Requires the `agent:approve` permission.
 */
export function decideApproval(approvalId: string, approve: boolean, signal?: AbortSignal): Promise<ToolApproval> {
  return apiClient.post<ToolApproval>(`/api/v1/agent/approvals/${encodeURIComponent(approvalId)}/${approve ? 'approve' : 'deny'}`, undefined, { signal })
}
