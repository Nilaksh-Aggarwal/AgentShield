import type { ReactNode } from 'react'
import { presentRiskLevel } from '@/features/firewall'
import { Badge } from '@/shared/components/ui'
import type { AgentActionAuthorization } from '../api/authorizeAgentAction'
import type { AgentActionExample } from '../model'
import { presentActionDecision, presentAgentActionReason } from '../model'

// Columns from `md`: example, agent, tool and action, capability, risk, decision.
const columns = 'md:grid md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.1fr)_7rem_minmax(0,1.2fr)] md:items-start md:gap-x-4'

/**
 * The example agent actions and, once the preview ran, the decision the API returned for each. Before that, the risk and
 * decision columns say so: this list never predicts a decision.
 */
export function AgentPreviewList({
  examples,
  decisions,
}: {
  examples: readonly AgentActionExample[]
  decisions: ReadonlyMap<string, AgentActionAuthorization>
}) {
  return (
    <ol className="divide-y divide-border" aria-label="Example agent actions">
      <li aria-hidden="true" className={`hidden bg-background px-4 py-2 text-xs font-semibold tracking-wide text-muted uppercase sm:px-6 ${columns}`}>
        <span>Example</span>
        <span>Agent</span>
        <span>Tool and action</span>
        <span>Capability</span>
        <span>Risk</span>
        <span>Decision</span>
      </li>
      {examples.map((example) => (
        <PreviewRow key={example.id} example={example} authorization={decisions.get(example.id)} />
      ))}
    </ol>
  )
}

function PreviewRow({ example, authorization }: { example: AgentActionExample; authorization: AgentActionAuthorization | undefined }) {
  const { request } = example

  return (
    <li className={`grid gap-y-1.5 px-4 py-3 text-sm sm:px-6 ${columns}`}>
      <Cell label="Example">
        <span className="font-medium text-foreground">{example.title}</span>
        {request.inputDecision && <span className="block text-xs text-muted">Input decision reported: {request.inputDecision}</span>}
      </Cell>
      <Cell label="Agent">
        <Name>{request.agentId}</Name>
      </Cell>
      <Cell label="Tool and action">
        <Name>{`${request.tool}.${request.action}`}</Name>
      </Cell>
      <Cell label="Capability">
        <Name>{request.capability}</Name>
      </Cell>
      <Cell label="Risk">{authorization ? <span className="text-foreground">{presentRiskLevel(authorization.riskLevel).label}</span> : <NotRun />}</Cell>
      <Cell label="Decision">{authorization ? <Decision authorization={authorization} /> : <NotRun />}</Cell>
    </li>
  )
}

function Decision({ authorization }: { authorization: AgentActionAuthorization }) {
  const decision = presentActionDecision(authorization.decision)
  const reason = presentAgentActionReason(authorization.reason)

  return (
    <span className="flex flex-col items-start gap-1">
      <Badge tone={decision.tone}>
        {decision.label}
        <span className="sr-only">: {decision.action}</span>
      </Badge>
      <span className="text-xs font-medium text-foreground">{reason.label}</span>
      <span className="text-xs text-muted">{reason.explanation}</span>
    </span>
  )
}

function NotRun() {
  return <span className="text-muted">Not run yet</span>
}

function Name({ children }: { children: string }) {
  return <code className="font-mono text-xs break-all text-foreground">{children}</code>
}

/** One value of a row. Its label is visible on narrow screens and read by screen readers; from `md` the column header shows it. */
function Cell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 items-baseline gap-2 md:block">
      <span className="w-28 shrink-0 text-xs font-semibold text-muted md:sr-only">{label}</span>
      <span className="min-w-0">{children}</span>
    </div>
  )
}
