import { useMemo } from 'react'
import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { ArrowRightIcon, Badge, Button, ButtonLink, Card, CardHeader, ErrorIcon, InfoIcon, SpinnerIcon } from '@/shared/components/ui'
import type { AgentActionAuthorization } from '../api/authorizeAgentAction'
import { useAgentAuthorizationPreview } from '../hooks/useAgentAuthorizationPreview'
import { agentActionExamples, presentAgentSecurityError } from '../model'
import { AgentPreviewList } from './AgentPreviewList'
import { AgentSecurityFlow } from './AgentSecurityFlow'
import { ApprovalsPanel } from './ApprovalsPanel'
import { ToolGatewayPreview } from './ToolGatewayPreview'

/**
 * Agent security preview: sends example agent actions to the real authorization boundary and shows the decisions it
 * returns (nothing is executed there), then example tool calls to the real tool gateway, which runs its one harmless
 * reference tool only on Allow. The agents and tools are example data, and nothing here is production telemetry.
 */
export function AgentSecurityPage() {
  const preview = useAgentAuthorizationPreview()
  const decisions = useMemo(
    () => new Map<string, AgentActionAuthorization>((preview.data ?? []).map((result) => [result.exampleId, result.authorization])),
    [preview.data],
  )

  const status = preview.isPending
    ? 'Asking the authorization boundary…'
    : preview.isSuccess
      ? `Decided ${preview.data.length} example ${preview.data.length === 1 ? 'action' : 'actions'}: ${count(preview.data, 'Allow')} allowed, ${count(preview.data, 'Review')} for review, ${count(preview.data, 'Block')} blocked.`
      : ''

  return (
    <section className="space-y-6" aria-labelledby="agents-heading">
      <DocumentTitle title="Agent security" />
      <PageHeader
        id="agents-heading"
        eyebrow="Agent security · Preview"
        title="Agent authorization preview"
        description={
          <p>
            Before an agent calls a tool, AgentShield decides whether it may: Allow, Review or Block. The first preview sends
            example agent actions to the real authorization boundary, which only decides: nothing is executed there. The second
            sends example tool calls to the tool gateway, which runs its one reference tool only when the decision is Allow.
          </p>
        }
        actions={
          <Button onClick={() => preview.mutate(agentActionExamples)} disabled={preview.isPending}>
            {preview.isPending && <SpinnerIcon />}
            {preview.isSuccess ? 'Run the examples again' : 'Run the examples'}
          </Button>
        }
      />

      <PreviewNotice />
      <AgentSecurityFlow />

      <p role="status" className="sr-only">
        {status}
      </p>

      {preview.isError && <PreviewErrorCard error={preview.error} />}

      <Card as="section" padding="none" aria-labelledby="examples-heading" aria-busy={preview.isPending}>
        <CardHeader
          id="examples-heading"
          title="Example agent actions"
          description={
            preview.isSuccess
              ? 'Decisions as the authorization boundary returned them. Each one is also recorded in Activity.'
              : 'Run the examples to see the decisions. Each request is recorded in Activity.'
          }
          actions={
            preview.isSuccess ? (
              <ButtonLink to="/activity" variant="secondary">
                Open Activity
                <ArrowRightIcon />
              </ButtonLink>
            ) : undefined
          }
        />
        <AgentPreviewList examples={agentActionExamples} decisions={decisions} />
      </Card>

      <ToolGatewayPreview />
      <ApprovalsPanel />

      <HowTheBoundaryDecides />
      <BuiltAndNext />
    </section>
  )
}

function count(results: readonly { authorization: AgentActionAuthorization }[], decision: string): number {
  return results.filter((result) => result.authorization.decision === decision).length
}

function PreviewNotice() {
  return (
    <Card as="section" aria-labelledby="preview-notice-heading" className="flex gap-3">
      <InfoIcon className="mt-0.5 size-5 shrink-0 text-primary" />
      <div className="min-w-0 space-y-2">
        <h2 id="preview-notice-heading" className="flex flex-wrap items-center gap-2 text-sm font-semibold text-foreground">
          Example data, not production telemetry
          <Badge tone="info">Preview</Badge>
        </h2>
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
          <li>The agents, tools and capabilities are examples from the development configuration, not real agents.</li>
          <li>The authorization preview only decides. The tool gateway runs one harmless reference tool, a lookup in a small built-in dataset, only on Allow or after a person approves a held call; other tools are decided, not enforced.</li>
          <li>The decisions are real: they come from the same authorization boundary and policy the API applies to every request.</li>
        </ul>
      </div>
    </Card>
  )
}

function PreviewErrorCard({ error }: { error: unknown }) {
  const presentation = presentAgentSecurityError(error)

  return (
    <section role="alert" aria-labelledby="agents-error-heading" className="flex gap-3 rounded-lg border border-danger/30 bg-danger/10 p-4 sm:p-6">
      <ErrorIcon className="mt-0.5 size-5 text-danger" />
      <div className="min-w-0 space-y-1.5">
        <h2 id="agents-error-heading" className="font-semibold text-danger">
          {presentation.title}
        </h2>
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

const steps = [
  { title: 'A known agent, bound to the caller', text: 'The agent must be configured in AgentShield, and the application asking must be allowed to act for it.' },
  { title: 'A catalogued tool action', text: 'Each action of a tool has its own entry: reading email and sending email are different actions.' },
  { title: 'Exactly the required capability, held by the agent', text: 'Capabilities come from AgentShield’s configuration. What the agent claims never grants anything.' },
  { title: 'The action’s risk', text: 'Classified from what the action does (reads, writes, communicates externally, moves money…), never by an AI model.' },
] as const

const outcomes = [
  { risk: 'Low or medium risk', decision: 'Allow', tone: 'success' },
  { risk: 'High risk', decision: 'Review', tone: 'warning' },
  { risk: 'Critical risk', decision: 'Block', tone: 'danger' },
  { risk: 'Anything unknown or not granted', decision: 'Block', tone: 'danger' },
] as const

function HowTheBoundaryDecides() {
  return (
    <Card as="section" aria-labelledby="how-decides-heading" className="space-y-4">
      <h2 id="how-decides-heading" className="text-lg font-semibold tracking-tight text-foreground">
        How the boundary decides
      </h2>
      <ol className="grid gap-3 md:grid-cols-2">
        {steps.map((step, index) => (
          <li key={step.title} className="flex gap-3 rounded-lg border border-border p-3">
            <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary" aria-hidden="true">
              {index + 1}
            </span>
            <span className="min-w-0 text-sm">
              <span className="block font-medium text-foreground">{step.title}</span>
              <span className="text-muted">{step.text}</span>
            </span>
          </li>
        ))}
      </ol>
      <ul className="grid gap-2 sm:grid-cols-2" aria-label="Decisions by risk">
        {outcomes.map((outcome) => (
          <li key={outcome.risk} className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2 text-sm">
            <span className="text-foreground">{outcome.risk}</span>
            <Badge tone={outcome.tone}>{outcome.decision}</Badge>
          </li>
        ))}
      </ul>
      <p className="text-sm text-muted">
        The agent cannot lift a decision: an input that was held for review or blocked keeps the action held or blocked, and a
        higher risk never leads to a more permissive decision. Only Allow means the action may run.
      </p>
    </Card>
  )
}

function BuiltAndNext() {
  return (
    <Card as="section" aria-labelledby="built-next-heading" className="space-y-4">
      <h2 id="built-next-heading" className="text-lg font-semibold tracking-tight text-foreground">
        What exists today, and what comes next
      </h2>
      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">Built</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
            <li>The authorization decision: capability check, risk classification and policy</li>
            <li>A tool gateway that runs its reference tool only on Allow, or once after a person approves a held call, with argument checks and a single-use grant</li>
            <li>At the gateway, the API key is the agent: it cannot act as another one</li>
            <li>Every decision and every execution recorded in the audit log and in Activity, as metadata</li>
          </ul>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">Not built yet</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
            <li>Enforcement for real tools: the gateway runs one built-in reference tool, so other tool calls are still up to the application</li>
            <li>Tool integrations such as MCP, and argument checks for tools other than the reference tool</li>
            <li>Screening of tool output and protection of agent memory</li>
          </ul>
        </div>
      </div>
    </Card>
  )
}
