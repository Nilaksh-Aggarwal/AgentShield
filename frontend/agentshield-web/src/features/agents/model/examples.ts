import type { AgentActionRequest } from '../api/authorizeAgentAction'

export interface AgentActionExample {
  id: string
  /** What the example shows, in a few words. */
  title: string
  request: AgentActionRequest
}

/**
 * Example agent actions for the authorization preview: deterministic test data that matches the demo agents in the API's
 * Development configuration (support, research, operations and finance agents). They are not real agents or real
 * telemetry, and the console never states what the API will decide: the decision shown is always the one it returned.
 */
export const agentActionExamples: readonly AgentActionExample[] = [
  { id: 'safe-read', title: 'Read data it is allowed to read', request: { agentId: 'research-agent', tool: 'data', action: 'read', capability: 'data:read' } },
  { id: 'draft', title: 'Draft an email for approval', request: { agentId: 'support-agent', tool: 'email', action: 'draft', capability: 'email:draft' } },
  { id: 'send', title: 'Send an email outside the organisation', request: { agentId: 'support-agent', tool: 'email', action: 'send', capability: 'email:send' } },
  { id: 'no-capability', title: 'Use a tool it holds no capability for', request: { agentId: 'research-agent', tool: 'email', action: 'send', capability: 'email:send' } },
  { id: 'borrowed', title: 'Write with a read capability', request: { agentId: 'research-agent', tool: 'data', action: 'write', capability: 'data:read' } },
  { id: 'escalation', title: 'Grant itself a role', request: { agentId: 'support-agent', tool: 'identity', action: 'grant', capability: 'identity:grant' } },
  { id: 'critical', title: 'Execute a payment it holds the capability for', request: { agentId: 'finance-agent', tool: 'payment', action: 'execute', capability: 'payment:execute' } },
  { id: 'unknown-tool', title: 'Call a tool AgentShield does not know', request: { agentId: 'support-agent', tool: 'shell', action: 'exec', capability: 'shell:exec' } },
  {
    id: 'input-blocked',
    title: 'Safe read after a blocked input',
    request: { agentId: 'research-agent', tool: 'data', action: 'read', capability: 'data:read', inputDecision: 'Block' },
  },
]
