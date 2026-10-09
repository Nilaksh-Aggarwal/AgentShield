import type { ComponentType, ReactNode } from 'react'
import { presentAgentActionReason, presentToolOutcome } from '@/features/agents'
import { presentDecision, presentRiskLevel } from '@/features/firewall'
import { Badge, BlockIcon, CheckCircleIcon, ChevronDownIcon, CodeIcon, LockIcon, ShieldIcon, WarningIcon, type IconProps } from '@/shared/components/ui'
import type { ActivityAgentAction, ActivityItem, ActivityToolExecution } from '../api/listActivity'
import { parseOccurredAt, presentActivityKind, presentAiStatus, summariseFindings } from '../model'

const decisionIcon: Readonly<Record<string, ComponentType<IconProps>>> = {
  Allow: CheckCircleIcon,
  Review: WarningIcon,
  Block: BlockIcon,
}

const kindIcon: Readonly<Record<string, ComponentType<IconProps>>> = {
  InputAnalysis: ShieldIcon,
  AgentActionAuthorization: LockIcon,
  ToolExecution: CodeIcon,
}

// Columns from `md`: time, decision, risk, details (findings or agent action), AI analysis, disclosure marker.
const columns = 'md:grid md:grid-cols-[9.5rem_7rem_8rem_minmax(0,1fr)_7.5rem_1rem] md:items-center md:gap-x-4'

const timeFormat = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })

/**
 * Security events, newest first. Every value comes from the API's metadata; there is no field for the analysed text, so
 * none can be shown. Each row opens to its trace IDs.
 */
export function ActivityList({ items }: { items: readonly ActivityItem[] }) {
  return (
    <ol className="divide-y divide-border" aria-label="Security events, newest first">
      <li aria-hidden="true" className={`hidden bg-background px-4 py-2 text-xs font-semibold tracking-wide text-muted uppercase sm:px-6 ${columns}`}>
        <span>Time</span>
        <span>Decision</span>
        <span>Risk</span>
        <span>Details</span>
        <span>AI analysis</span>
      </li>
      {items.map((item) => (
        <ActivityRow key={item.securityEventId} item={item} />
      ))}
    </ol>
  )
}

function ActivityRow({ item }: { item: ActivityItem }) {
  const decision = presentDecision(item.decision)
  const DecisionIcon = (Object.hasOwn(decisionIcon, item.decision) ? decisionIcon[item.decision] : undefined) ?? WarningIcon
  const risk = presentRiskLevel(item.risk.level)
  const findings = summariseFindings(item.findings)
  const isAgentKind = item.kind === 'AgentActionAuthorization' || item.kind === 'ToolExecution'
  const agentAction = isAgentKind ? (item.agentAction ?? undefined) : undefined
  const toolExecution = item.kind === 'ToolExecution' ? (item.toolExecution ?? undefined) : undefined
  const ai = isAgentKind ? { label: 'Not applicable', tone: 'neutral' } : presentAiStatus(item.aiAnalysis)
  const occurredAt = parseOccurredAt(item.occurredAt)

  return (
    <li>
      <details className="group">
        <summary
          className={`grid min-h-11 cursor-pointer list-none gap-y-1.5 px-4 py-3 text-sm hover:bg-background sm:px-6 [&::-webkit-details-marker]:hidden ${columns}`}
        >
          <Cell label="Time">
            {occurredAt ? (
              <time dateTime={occurredAt.toISOString()} className="tabular-nums text-foreground">
                {timeFormat.format(occurredAt)}
              </time>
            ) : (
              <span className="text-muted">Unknown time</span>
            )}
          </Cell>
          <Cell label="Decision">
            <Badge tone={decision.tone}>
              <DecisionIcon className="size-3.5" />
              {decision.label}
            </Badge>
          </Cell>
          <Cell label="Risk">
            {typeof item.risk.score === 'number' && (
              <>
                <span className="font-semibold tabular-nums text-foreground">{item.risk.score}</span>{' '}
              </>
            )}
            <span className="text-muted">{risk.label}</span>
          </Cell>
          <Cell label="Details">
            <KindBadge kind={item.kind} />
            {agentAction ? (
              <AgentActionSummary action={agentAction} execution={toolExecution} />
            ) : findings.primary ? (
              <span className="text-foreground">
                {findings.primary}
                {findings.more > 0 && <span className="text-muted"> and {findings.more} more</span>}
              </span>
            ) : (
              <span className="text-muted">No findings</span>
            )}
          </Cell>
          <Cell label="AI analysis">
            <span className={ai.tone === 'warning' ? 'font-medium text-warning' : 'text-muted'}>{ai.label}</span>
          </Cell>
          <ChevronDownIcon className="hidden size-4 text-muted motion-safe:transition-transform group-open:rotate-180 md:block" />
        </summary>
        <dl className="grid gap-x-6 gap-y-2 border-t border-border bg-background px-4 py-3 text-sm sm:grid-cols-[auto_minmax(0,1fr)] sm:px-6">
          <dt className="text-muted">Security event ID</dt>
          <dd>
            <code className="font-mono text-xs break-all text-foreground">{item.securityEventId}</code>
          </dd>
          <dt className="text-muted">Correlation ID</dt>
          <dd>
            <code className="font-mono text-xs break-all text-foreground">{item.correlationId}</code>
          </dd>
          {agentAction && (
            <>
              <dt className="text-muted">Capability claimed</dt>
              <dd>{agentAction.capability ? <code className="font-mono text-xs break-all text-foreground">{agentAction.capability}</code> : <span className="text-muted">Not recognised</span>}</dd>
              <dt className="text-muted">Reason</dt>
              <dd className="text-foreground">{presentAgentActionReason(agentAction.reason).explanation}</dd>
            </>
          )}
          {toolExecution && <ToolExecutionDetails execution={toolExecution} />}
        </dl>
      </details>
    </li>
  )
}

/** What the record is about, ahead of its details: an input, an agent action or a tool call. Unknown kinds are not echoed. */
function KindBadge({ kind }: { kind: unknown }) {
  const presentation = presentActivityKind(kind)
  const Icon = typeof kind === 'string' && Object.hasOwn(kindIcon, kind) ? kindIcon[kind] : undefined
  return (
    <>
      <Badge tone={presentation.agent ? 'info' : 'neutral'} className="mr-2 align-middle">
        {Icon && <Icon className="size-3.5" />}
        {presentation.label}
      </Badge>
      <span className="sr-only">: </span>
    </>
  )
}

/**
 * An agent action in one line: which agent wanted to run which action, and why it was decided so. A name AgentShield did not
 * recognise arrives as `null` and is shown as unknown; nothing the caller made up is shown.
 */
function AgentActionSummary({ action, execution }: { action: ActivityAgentAction; execution: ActivityToolExecution | undefined }) {
  const tool = action.tool ?? 'unknown tool'
  // A tool call leads with what the gateway did (the boundary's reason is in the details); an authorization with its reason.
  const why = execution ? presentToolOutcome(execution.outcome).label : presentAgentActionReason(action.reason).label
  return (
    <span className="text-foreground">
      {action.agentId ?? 'unknown agent'} <span className="text-muted">→</span> {action.action ? `${tool}.${action.action}` : `${tool}, unknown action`}
      <span className="text-muted"> · {why}</span>
    </span>
  )
}

/**
 * What the gateway did with a tool call. "Tool ran" needs both the record's `executed` flag and the `Executed` outcome: a
 * record that says less, or an outcome this console does not know, is never shown as a tool that ran.
 */
function ToolExecutionDetails({ execution }: { execution: ActivityToolExecution }) {
  const outcome = presentToolOutcome(execution.outcome)
  const ran = execution.executed === true && execution.outcome === 'Executed'
  return (
    <>
      <dt className="text-muted">Tool</dt>
      <dd className="text-foreground">{ran ? 'Ran once' : 'Did not run'}</dd>
      <dt className="text-muted">What happened</dt>
      <dd className="text-foreground">{outcome.explanation}</dd>
      {typeof execution.executionId === 'string' && (
        <>
          <dt className="text-muted">Execution ID</dt>
          <dd>
            <code className="font-mono text-xs break-all text-foreground">{execution.executionId}</code>
          </dd>
        </>
      )}
    </>
  )
}

/** One value of a row. Its label is visible on narrow screens and read by screen readers; from `md` the column header shows it. */
function Cell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 items-baseline gap-2 md:block">
      <span className="w-24 shrink-0 text-xs font-semibold text-muted md:sr-only">{label}</span>
      <span className="min-w-0">{children}</span>
    </div>
  )
}
