import { useMutation, useQueryClient } from '@tanstack/react-query'
import { runScenario } from '../api/runScenario'
import type { AttackScenario } from '../model/scenarios'

/**
 * Runs one scenario against the real API. Each run records security events on the server and may run the reference tool,
 * so it is a mutation (never retried automatically), not a cached query. Activity is refetched afterwards, whatever the
 * outcome, because a failed run can still have recorded events.
 */
export function useScenarioRun() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationKey: ['attack-lab', 'run'],
    mutationFn: (scenario: AttackScenario) => runScenario(scenario),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['activity'] }),
  })
}
