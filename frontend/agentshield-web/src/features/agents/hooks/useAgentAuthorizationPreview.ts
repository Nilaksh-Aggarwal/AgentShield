import { useMutation } from '@tanstack/react-query'
import { authorizeAgentAction, type AgentActionAuthorization } from '../api/authorizeAgentAction'
import type { AgentActionExample } from '../model/examples'

export interface PreviewResult {
  exampleId: string
  authorization: AgentActionAuthorization
}

/**
 * Sends each example to the authorization boundary, one after another, and stops at the first failure. Each decision is
 * recorded as a security event on the server, so this is a mutation (never retried automatically), not a cached query.
 */
export function useAgentAuthorizationPreview() {
  return useMutation({
    mutationKey: ['agents', 'authorization-preview'],
    mutationFn: async (examples: readonly AgentActionExample[]): Promise<PreviewResult[]> => {
      const results: PreviewResult[] = []
      for (const example of examples) {
        results.push({ exampleId: example.id, authorization: await authorizeAgentAction(example.request) })
      }

      return results
    },
  })
}
