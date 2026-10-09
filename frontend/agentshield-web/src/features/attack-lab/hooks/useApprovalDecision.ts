import { useMutation, useQueryClient } from '@tanstack/react-query'
import { decideApprovalRun, type ApprovalRun } from '../api/runScenario'
import type { ApprovalScenario } from '../model/scenarios'

/**
 * A person's decision on the held call of the approval scenario, then the agent presenting the approval with the same call.
 * Both change server state (the approval, possibly a tool run), so this is a mutation, never retried automatically. Activity
 * and the approvals list are refetched afterwards, whatever the outcome.
 */
export function useApprovalDecision() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationKey: ['attack-lab', 'approval'],
    mutationFn: ({ scenario, run, approve }: { scenario: ApprovalScenario; run: ApprovalRun; approve: boolean }) => decideApprovalRun(scenario, run, approve),
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ['activity'] })
      await queryClient.invalidateQueries({ queryKey: ['agents', 'approvals'] })
    },
  })
}
