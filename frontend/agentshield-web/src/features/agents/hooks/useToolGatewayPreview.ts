import { useMutation } from '@tanstack/react-query'
import { executeTool, type ToolExecution } from '../api/executeTool'
import type { ToolGatewayExample } from '../model/gatewayExamples'

export interface GatewayPreviewResult {
  exampleId: string
  execution: ToolExecution
}

/**
 * Sends each example to the tool gateway, one after another, and stops at the first failure. Each request is recorded on
 * the server and may run a tool, so this is a mutation (never retried automatically), not a cached query.
 */
export function useToolGatewayPreview() {
  return useMutation({
    mutationKey: ['agents', 'tool-gateway-preview'],
    mutationFn: async (examples: readonly ToolGatewayExample[]): Promise<GatewayPreviewResult[]> => {
      const results: GatewayPreviewResult[] = []
      for (const example of examples) {
        results.push({ exampleId: example.id, execution: await executeTool(example.request) })
      }

      return results
    },
  })
}
