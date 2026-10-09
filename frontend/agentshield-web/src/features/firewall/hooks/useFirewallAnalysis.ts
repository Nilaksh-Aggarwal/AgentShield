import { useMutation } from '@tanstack/react-query'
import { analyzeInput } from '../api/analyzeInput'

/**
 * Analysing records a security event on the server, so it is a mutation (never retried automatically),
 * not a cached query.
 */
export function useFirewallAnalysis() {
  return useMutation({
    mutationKey: ['firewall', 'analyze'],
    mutationFn: (input: string) => analyzeInput({ input }),
  })
}
