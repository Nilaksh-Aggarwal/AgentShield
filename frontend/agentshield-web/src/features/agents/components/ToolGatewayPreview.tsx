import { useMemo, type ReactNode } from 'react'
import { presentRiskLevel } from '@/features/firewall'
import { Badge, Button, Card, CardHeader, ErrorIcon, SpinnerIcon } from '@/shared/components/ui'
import type { ToolExecution } from '../api/executeTool'
import { useToolGatewayPreview } from '../hooks/useToolGatewayPreview'
import {
  describeArguments,
  presentActionDecision,
  presentAgentActionReason,
  presentToolGatewayError,
  presentToolOutcome,
  resultText,
  toolGatewayExamples,
  toolRan,
  type ToolGatewayExample,
} from '../model'

// Columns from `md`: example, tool and action, arguments, decision, what happened.
const columns = 'md:grid md:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)_minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.5fr)] md:items-start md:gap-x-4'

/**
 * Tool gateway preview: sends example tool calls to the real gateway, which runs the one reference tool
 * (`knowledge.lookup`, a fixed in-memory dataset) only on Allow, and shows what it did. The examples act as the demo
 * research agent, whose identity is the Development API key.
 */
export function ToolGatewayPreview() {
  const preview = useToolGatewayPreview()
  const executions = useMemo(
    () => new Map<string, ToolExecution>((preview.data ?? []).map((result) => [result.exampleId, result.execution])),
    [preview.data],
  )

  const ran = (preview.data ?? []).filter((result) => toolRan(result.execution)).length
  const status = preview.isPending
    ? 'Sending the tool calls to the gateway…'
    : preview.isSuccess
      ? `Sent ${preview.data.length} example tool ${preview.data.length === 1 ? 'call' : 'calls'}: the tool ran for ${ran}, and for ${preview.data.length - ran} it did not.`
      : ''

  return (
    <Card as="section" padding="none" aria-labelledby="gateway-heading" aria-busy={preview.isPending}>
      <CardHeader
        id="gateway-heading"
        title="Tool gateway: enforced execution"
        description={
          <>
            Here AgentShield also runs the tool, and only on Allow (a call held for review runs only after a person approves it): it holds the tool, issues a single-use grant for exactly the
            allowed call, and checks it before the tool runs. The agent never holds anything that runs a tool. The one tool is a
            harmless lookup in a small built-in dataset; the examples act as the demo research agent.
          </>
        }
        actions={
          <Button onClick={() => preview.mutate(toolGatewayExamples)} disabled={preview.isPending}>
            {preview.isPending && <SpinnerIcon />}
            {preview.isSuccess ? 'Run the gateway examples again' : 'Run the gateway examples'}
          </Button>
        }
      />

      {/* A live region without the status role, so the authorization preview's status stays the page's one status. */}
      <p aria-live="polite" className="sr-only">
        {status}
      </p>

      {preview.isError && <GatewayErrorCard error={preview.error} />}

      <ol className="divide-y divide-border" aria-label="Example tool calls">
        <li aria-hidden="true" className={`hidden bg-background px-4 py-2 text-xs font-semibold tracking-wide text-muted uppercase sm:px-6 ${columns}`}>
          <span>Example</span>
          <span>Tool and action</span>
          <span>Arguments</span>
          <span>Decision</span>
          <span>What happened</span>
        </li>
        {toolGatewayExamples.map((example) => (
          <GatewayRow key={example.id} example={example} execution={executions.get(example.id)} />
        ))}
      </ol>
    </Card>
  )
}

function GatewayRow({ example, execution }: { example: ToolGatewayExample; execution: ToolExecution | undefined }) {
  const { request } = example

  return (
    <li className={`grid gap-y-1.5 px-4 py-3 text-sm sm:px-6 ${columns}`}>
      <Cell label="Example">
        <span className="font-medium text-foreground">{example.title}</span>
        {request.inputDecision && <span className="block text-xs text-muted">Input decision reported: {request.inputDecision}</span>}
      </Cell>
      <Cell label="Tool and action">
        <Name>{`${request.tool}.${request.action}`}</Name>
      </Cell>
      <Cell label="Arguments">
        <Name>{describeArguments(request)}</Name>
      </Cell>
      <Cell label="Decision">{execution ? <Decision execution={execution} /> : <NotRun />}</Cell>
      <Cell label="What happened">{execution ? <Outcome execution={execution} /> : <NotRun />}</Cell>
    </li>
  )
}

function Decision({ execution }: { execution: ToolExecution }) {
  const decision = presentActionDecision(execution.decision)
  const reason = presentAgentActionReason(execution.authorizationReason)

  return (
    <span className="flex flex-col items-start gap-1">
      <Badge tone={decision.tone}>
        {decision.label}
        <span className="sr-only">: {decision.action}</span>
      </Badge>
      <span className="text-xs text-muted">
        {presentRiskLevel(execution.riskLevel).label} · Authorization: {reason.label}
      </span>
    </span>
  )
}

function Outcome({ execution }: { execution: ToolExecution }) {
  const ran = toolRan(execution)
  const outcome = presentToolOutcome(execution.outcome)
  const text = resultText(execution)

  return (
    <span className="flex flex-col items-start gap-1">
      <span className={`text-xs font-semibold ${ran ? 'text-success' : 'text-foreground'}`}>{ran ? 'The tool ran' : 'The tool did not run'}</span>
      <span className="text-xs text-muted">
        {outcome.label}: {outcome.explanation}
      </span>
      {ran && (text ? <span className="text-xs text-foreground">{text}</span> : <span className="text-xs text-muted">The dataset has nothing on this topic.</span>)}
    </span>
  )
}

function GatewayErrorCard({ error }: { error: unknown }) {
  const presentation = presentToolGatewayError(error)

  return (
    <section role="alert" aria-labelledby="gateway-error-heading" className="m-4 flex gap-3 rounded-lg border border-danger/30 bg-danger/10 p-4 sm:mx-6">
      <ErrorIcon className="mt-0.5 size-5 text-danger" />
      <div className="min-w-0 space-y-1.5">
        <h3 id="gateway-error-heading" className="font-semibold text-danger">
          {presentation.title}
        </h3>
        <p className="text-sm text-foreground">{presentation.description}</p>
        {presentation.reference && (
          <p className="text-xs text-muted">
            Reference <code className="font-mono break-all">{presentation.reference}</code>
          </p>
        )}
      </div>
    </section>
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
