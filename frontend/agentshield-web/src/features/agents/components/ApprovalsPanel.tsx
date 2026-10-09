import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { presentRiskLevel } from '@/features/firewall'
import { Badge, Button, Card, CardHeader, ErrorIcon, SpinnerIcon } from '@/shared/components/ui'
import { decideApproval, listApprovals, type ToolApproval } from '../api/approvals'
import { presentAgentActionReason, presentApprovalError, presentApprovalStatus } from '../model'

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })

function time(value: unknown): string {
  if (typeof value !== 'string') {
    return 'unknown time'
  }

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'unknown time' : timeFormat.format(date)
}

/**
 * Human approval: the tool calls the gateway held for review, from the real API, with Approve and Deny for the pending ones.
 * Approving runs nothing here: it lets the agent run exactly that call once. Only clients holding the approval permission
 * see the list (the public Development key holds it, for the demo).
 */
export function ApprovalsPanel() {
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState('')
  const approvals = useQuery({ queryKey: ['agents', 'approvals'], queryFn: ({ signal }) => listApprovals(signal), staleTime: 0 })
  const decision = useMutation({
    mutationKey: ['agents', 'approvals', 'decide'],
    mutationFn: ({ approvalId, approve }: { approvalId: string; approve: boolean }) => decideApproval(approvalId, approve),
    onSuccess: (approval) => setFeedback(`${presentApprovalStatus(approval.status).label}: ${presentApprovalStatus(approval.status).explanation}`),
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ['agents', 'approvals'] })
      await queryClient.invalidateQueries({ queryKey: ['activity'] })
    },
  })

  const items = approvals.data?.items ?? []

  return (
    <Card as="section" padding="none" aria-labelledby="approvals-heading" aria-busy={approvals.isFetching || decision.isPending}>
      <CardHeader
        id="approvals-heading"
        title="Human approval: held tool calls"
        description="Calls the tool gateway held for review, waiting for a person. Approving lets the agent run exactly that call once, before the approval expires; denying means it never runs. Nothing here runs a tool."
        actions={
          <Button variant="secondary" onClick={() => void approvals.refetch()} disabled={approvals.isFetching}>
            {approvals.isFetching && <SpinnerIcon />}
            Refresh
          </Button>
        }
      />

      {/* A live region without the status role, so the authorization preview's status stays the page's one status. */}
      <p aria-live="polite" className="sr-only">
        {feedback}
      </p>

      {decision.isError && <ApprovalError error={decision.error} />}

      {approvals.isPending ? (
        <p className="px-4 py-4 text-sm text-muted sm:px-6">Loading the held calls…</p>
      ) : approvals.isError ? (
        <ApprovalError error={approvals.error} />
      ) : items.length === 0 ? (
        <p className="px-4 py-4 text-sm text-muted sm:px-6">No tool call is waiting for a person. Run scenario T-04 in the Attack Lab to hold one.</p>
      ) : (
        <ul className="divide-y divide-border" aria-label="Held tool calls, newest first">
          {items.map((approval) => (
            <ApprovalItem
              key={approval.approvalId}
              approval={approval}
              deciding={decision.isPending && decision.variables.approvalId === approval.approvalId}
              disabled={decision.isPending}
              onDecide={(approve) => decision.mutate({ approvalId: approval.approvalId, approve })}
            />
          ))}
        </ul>
      )}
    </Card>
  )
}

function ApprovalItem({
  approval,
  deciding,
  disabled,
  onDecide,
}: {
  approval: ToolApproval
  deciding: boolean
  disabled: boolean
  onDecide: (approve: boolean) => void
}) {
  const status = presentApprovalStatus(approval.status)
  const reason = presentAgentActionReason(approval.reason)
  const risk = presentRiskLevel(typeof approval.riskLevel === 'string' ? approval.riskLevel : '')
  const call = typeof approval.tool === 'string' && typeof approval.action === 'string' ? `${approval.tool}.${approval.action}` : 'unknown action'

  return (
    <li className="space-y-3 px-4 py-4 sm:px-6">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={status.tone} size="md">
          {status.label}
        </Badge>
        <span className="text-sm text-muted">{status.explanation}</span>
      </div>
      <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[auto_minmax(0,1fr)]">
        <dt className="text-muted">Agent</dt>
        <dd>
          <code className="font-mono text-xs break-all text-foreground">{typeof approval.agentId === 'string' ? approval.agentId : 'unknown agent'}</code>
        </dd>
        <dt className="text-muted">Tool and action</dt>
        <dd>
          <code className="font-mono text-xs break-all text-foreground">{call}</code>
        </dd>
        <dt className="text-muted">Risk</dt>
        <dd className="text-foreground">{risk.label}</dd>
        <dt className="text-muted">Reason</dt>
        <dd className="text-foreground">{reason.explanation}</dd>
        <dt className="text-muted">Requested / expires</dt>
        <dd className="text-foreground tabular-nums">
          {time(approval.requestedAt)} / {time(approval.expiresAt)}
        </dd>
      </dl>
      {status.pending && (
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => onDecide(true)} disabled={disabled}>
            {deciding && <SpinnerIcon />}
            Approve
          </Button>
          <Button variant="secondary" onClick={() => onDecide(false)} disabled={disabled}>
            Deny
          </Button>
        </div>
      )}
    </li>
  )
}

function ApprovalError({ error }: { error: unknown }) {
  const presentation = presentApprovalError(error)
  return (
    <div role="alert" className="m-4 flex gap-3 rounded-lg border border-danger/30 bg-danger/10 p-4 sm:mx-6">
      <ErrorIcon className="mt-0.5 size-5 shrink-0 text-danger" />
      <div className="min-w-0 space-y-1 text-sm">
        <h3 className="font-semibold text-danger">{presentation.title}</h3>
        <p className="text-foreground">{presentation.description}</p>
        {presentation.reference && (
          <p className="text-xs text-muted">
            Reference <code className="font-mono break-all">{presentation.reference}</code>
          </p>
        )}
      </div>
    </div>
  )
}
