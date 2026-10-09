import type { ReactNode } from 'react'
import { describeArguments, type ToolExecutionRequest } from '@/features/agents'
import { Badge, Button, Card, ChevronDownIcon, InfoIcon, SpinnerIcon } from '@/shared/components/ui'
import { describeIntent } from '../model/evidence'
import type { AttackScenario } from '../model/scenarios'

interface ScenarioBriefProps {
  scenario: AttackScenario
  onRun: () => void
  /** This scenario is running. */
  running: boolean
  /** Some scenario is running: one at a time. */
  busy: boolean
  hasRun: boolean
}

/** The selected scenario: what it tries, what it sends, and the button that sends it to the live API. */
export function ScenarioBrief({ scenario, onRun, running, busy, hasRun }: ScenarioBriefProps) {
  return (
    <Card as="section" padding="none" aria-labelledby="scenario-heading">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border px-4 py-4 sm:px-6">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge>
              <span className="font-mono">{scenario.id}</span>
            </Badge>
            <Badge tone={scenario.category === 'Known miss' ? 'warning' : 'info'}>{scenario.category}</Badge>
            {scenario.owasp && <span className="text-xs text-muted">OWASP {scenario.owasp}</span>}
          </div>
          <h2 id="scenario-heading" className="text-xl font-semibold tracking-tight text-foreground">
            {scenario.title}
          </h2>
          <p className="max-w-2xl text-foreground">{scenario.summary}</p>
        </div>
        <Button onClick={onRun} disabled={busy}>
          {running && <SpinnerIcon />}
          {running ? 'Running…' : hasRun ? 'Run again' : 'Run scenario'}
        </Button>
      </div>

      <dl className="grid gap-x-6 gap-y-4 px-4 py-4 text-sm sm:grid-cols-[auto_minmax(0,1fr)] sm:gap-y-3 sm:px-6">
        <Fact term="Demonstrates">{scenario.demonstrates}</Fact>
        <Fact term="Sends">
          <Request scenario={scenario} />
        </Fact>
        <Fact term="Written to show">
          <span className="text-muted">{describeIntent(scenario)}. The result shown is always the API’s answer.</span>
        </Fact>
      </dl>

      {scenario.limitation && (
        <p className="flex gap-2 border-t border-border bg-background px-4 py-3 text-sm text-foreground sm:px-6">
          <InfoIcon className="mt-0.5 size-4 shrink-0 text-muted" />
          <span>
            <span className="font-semibold">Limitation: </span>
            {scenario.limitation}
          </span>
        </p>
      )}
    </Card>
  )
}

function Request({ scenario }: { scenario: AttackScenario }) {
  if (scenario.kind === 'input') {
    return (
      <div className="space-y-2">
        <p className="text-muted">
          <Endpoint>POST /api/v1/firewall/analyze</Endpoint> with this input:
        </p>
        <blockquote className="rounded-md border border-border bg-background px-3 py-2 break-words text-foreground">{scenario.display}</blockquote>
        {scenario.hidden && (
          <details className="group text-muted">
            <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 rounded-md [&::-webkit-details-marker]:hidden">
              <ChevronDownIcon className="size-4 motion-safe:transition-transform group-open:rotate-180" />
              What the encoded or hidden part says
            </summary>
            <p className="mt-1 rounded-md border border-border bg-background px-3 py-2 text-foreground">{scenario.hidden}</p>
          </details>
        )}
      </div>
    )
  }

  if (scenario.kind === 'approval') {
    return (
      <ol className="list-decimal space-y-2 pl-5 text-muted">
        <li>
          <Endpoint>POST /api/v1/firewall/analyze</Endpoint> with the document the agent read:
          <blockquote className="mt-1 rounded-md border border-border bg-background px-3 py-2 break-words text-foreground">{scenario.display}</blockquote>
        </li>
        <li>
          In the same trace, <Endpoint>POST /api/v1/agent/tools/execute</Endpoint> with the analysis’s security event as{' '}
          <code className="font-mono text-xs">inputEventId</code>, and a claim that the input was allowed:
          <div className="mt-1">
            <ToolCall request={scenario.request} />
          </div>
        </li>
        <li>
          You approve or deny. Then the same call again, with the returned <code className="font-mono text-xs">approvalId</code>.
        </li>
      </ol>
    )
  }

  return (
    <div className="space-y-2">
      <p className="text-muted">
        <Endpoint>POST /api/v1/agent/tools/execute</Endpoint> as the demo research agent (the API key says which agent; the request
        cannot):
      </p>
      <ToolCall request={scenario.request} />
      {scenario.kind === 'replay' && (
        <p className="text-muted">
          Then the same call again, adding the first response’s <code className="font-mono text-xs">executionId</code> as if it
          authorised another run.
        </p>
      )}
    </div>
  )
}

function ToolCall({ request }: { request: ToolExecutionRequest }) {
  return (
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 rounded-md border border-border bg-background px-3 py-2 text-xs">
      {request.inputDecision !== undefined && (
        <>
          <dt className="text-muted">Input claimed</dt>
          <dd>
            <code className="font-mono break-all text-foreground">{request.inputDecision}</code>
          </dd>
        </>
      )}
      <dt className="text-muted">Tool action</dt>
      <dd>
        <code className="font-mono break-all text-foreground">{`${request.tool}.${request.action}`}</code>
      </dd>
      <dt className="text-muted">Capability claimed</dt>
      <dd>
        <code className="font-mono break-all text-foreground">{request.capability}</code>
      </dd>
      <dt className="text-muted">Arguments</dt>
      <dd>
        <code className="font-mono break-all text-foreground">{describeArguments(request, 200)}</code>
      </dd>
    </dl>
  )
}

function Endpoint({ children }: { children: string }) {
  return <code className="font-mono text-xs break-all text-foreground">{children}</code>
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5 sm:contents">
      <dt className="text-muted">{term}</dt>
      <dd className="min-w-0 text-foreground">{children}</dd>
    </div>
  )
}
