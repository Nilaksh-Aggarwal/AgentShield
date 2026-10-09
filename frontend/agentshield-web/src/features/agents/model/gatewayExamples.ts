import type { ToolExecutionRequest } from '../api/executeTool'

export interface ToolGatewayExample {
  id: string
  /** What the example shows, in a few words. */
  title: string
  request: ToolExecutionRequest
}

/**
 * Example tool calls for the tool gateway preview. The Development API key is the gateway identity of the demo
 * `research-agent` (data:read, file:read, browser:navigate, knowledge:read), so every example acts as that agent: the
 * request has no agent field. The console never states what the gateway will do: what it shows is what the API returned.
 */
export const toolGatewayExamples: readonly ToolGatewayExample[] = [
  {
    id: 'lookup',
    title: 'Look up a topic it may read',
    request: { tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', arguments: { query: 'dependency injection' } },
  },
  {
    id: 'lookup-missing',
    title: 'Look up a topic the dataset does not have',
    request: { tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', arguments: { query: 'quantum gravity' } },
  },
  {
    id: 'smuggled-argument',
    title: 'Smuggle an extra argument into the call',
    request: { tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', arguments: { query: 'least privilege', path: '/etc/passwd' } },
  },
  {
    id: 'empty-query',
    title: 'Send an empty query',
    request: { tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', arguments: { query: '' } },
  },
  {
    id: 'high-risk',
    title: 'Open a web page (high risk)',
    request: { tool: 'browser', action: 'navigate', capability: 'browser:navigate', arguments: { url: 'https://example.com' } },
  },
  {
    id: 'not-granted',
    title: 'Send an email it holds no capability for',
    request: { tool: 'email', action: 'send', capability: 'email:send', arguments: { to: 'someone@example.com' } },
  },
  {
    id: 'no-tool',
    title: 'Read data: allowed, but no tool here runs it',
    request: { tool: 'data', action: 'read', capability: 'data:read', arguments: {} },
  },
  {
    id: 'input-blocked',
    title: 'Look up a topic after a blocked input',
    request: { tool: 'knowledge', action: 'lookup', capability: 'knowledge:read', arguments: { query: 'rate limiting' }, inputDecision: 'Block' },
  },
]
