import type { ComponentType, ReactNode } from 'react'
import {
  presentAgentActionReason,
  presentApprovalError,
  presentToolGatewayError,
  presentToolOutcome,
  resultText,
  toolRan,
  type ToolExecutionResult,
} from '@/features/agents'
import { FindingsSection, presentDecision, presentFinding, type FirewallAnalysisResult } from '@/features/firewall'
import {
  ArrowRightIcon,
  Badge,
  BlockIcon,
  Button,
  ButtonLink,
  Card,
  CheckCircleIcon,
  ErrorIcon,
  SpinnerIcon,
  WarningIcon,
  type IconProps,
  type Tone,
} from '@/shared/components/ui'
import type { ApprovalRun, ScenarioRun } from '../api/runScenario'
import {
  approvalTrail,
  compareWithIntent,
  describeIntent,
  inputTrail,
  presentApprovalDecision,
  presentRunDecision,
  presentRunRisk,
  replayStep,
  runDecision,
  runExecutedTool,
  toolTrail,
  type IntentComparison,
  type TrailStep,
} from '../model/evidence'
import type { AttackScenario } from '../model/scenarios'

// Class strings are written out in full so Tailwind can find them when scanning the source.
const bannerClass: Record<Tone, string> = {
  neutral: 'border-border bg-background',
  info: 'border-primary/30 bg-primary/10',
  success: 'border-success/30 bg-success/10',
  warning: 'border-warning/30 bg-warning/10',
  danger: 'border-danger/30 bg-danger/10',
  critical: 'border-danger/30 bg-danger/10',
}

const stepClass: Record<Tone, string> = {
  neutral: 'border-l-border',
  info: 'border-l-primary',
  success: 'border-l-success',
  warning: 'border-l-warning',
  danger: 'border-l-danger',
  critical: 'border-l-danger',
}

const decisionIcon: Readonly<Record<string, ComponentType<IconProps>>> = {
  Allow: CheckCircleIcon,
  Review: WarningIcon,
  Block: BlockIcon,
}

/** What a person can do about a held call shown in a result: decide it, while the decision is on its way, or what failed. */
export interface ApprovalControls {
  onDecide: (approve: boolean) => void
  deciding: boolean
  error: unknown
}

/** A completed run: the API's decision first, then each stage as the response reports it, then the evidence. */
export function RunResult({ scenario, run, approval }: { scenario: AttackScenario; run: ScenarioRun; approval?: ApprovalControls }) {
  const decision = runDecision(run)
  const DecisionIcon = (decision.known && Object.hasOwn(decisionIcon, decision.label) ? decisionIcon[decision.label] : undefined) ?? WarningIcon
  const ran = runExecutedTool(run)

  return (
    <Card as="section" padding="none" aria-labelledby="result-heading" className="overflow-hidden">
      <div className={`flex items-start gap-4 border-b p-4 sm:p-6 ${bannerClass[decision.tone]}`}>
        <span className="flex size-11 shrink-0 items-center justify-center rounded-full bg-surface shadow-xs" aria-hidden="true">
          <DecisionIcon className="size-6 text-foreground" />
        </span>
        <div className="min-w-0 space-y-2">
          <p className="text-xs font-semibold tracking-wide text-muted">Result from the live API</p>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={decision.tone} size="md" onTint>
              Decision: {decision.label}
            </Badge>
            {run.kind !== 'input' && (
              <Badge tone={ran ? 'success' : 'neutral'} size="md" onTint>
                {ran ? 'Tool ran' : 'Tool did not run'}
              </Badge>
            )}
          </div>
          <h2 id="result-heading" className="text-xl font-semibold tracking-tight text-foreground">
            {headline(run)}
          </h2>
        </div>
      </div>

      <div className="space-y-6 p-4 sm:p-6">
        <Trail steps={trail(run)} kind={run.kind === 'input' ? 'input' : 'agent'} />
        <Intent scenario={scenario} comparison={compareWithIntent(scenario, run)} />
        {run.kind === 'input' && <InputEvidence result={run.result} />}
        {run.kind === 'tool' && <GatewayEvidence result={run.result} />}
        {run.kind === 'replay' && (
          <>
            <GatewayEvidence result={run.first} heading="First request: the allowed lookup" />
            <ReplayEvidence run={run} />
          </>
        )}
        {run.kind === 'approval' && <ApprovalEvidence run={run} controls={approval} />}
        <div className="flex flex-wrap gap-2 border-t border-border pt-4">
          <ButtonLink to="/activity" variant="secondary">
            See it in Activity
            <ArrowRightIcon />
          </ButtonLink>
        </div>
      </div>
    </Card>
  )
}

function headline(run: ScenarioRun): string {
  if (run.kind === 'input') {
    const decision = runDecision(run)
    return decision.known ? presentDecision(decision.label).action : 'Decision not recognised: hold the input for review'
  }

  if (run.kind === 'replay') {
    return run.second.status === 'rejected' ? 'The lookup ran once; the replay was rejected' : 'The lookup ran; the replay was not rejected'
  }

  if (run.kind === 'approval') {
    if (run.final === undefined) {
      return run.held.execution.outcome === 'HeldForReview' && typeof run.held.execution.approvalId === 'string'
        ? 'Pending approval: nothing runs until a person decides'
        : 'The gateway did not hold the call for approval'
    }

    return toolRan(run.final.execution) ? 'Approved, and the gateway ran the call once' : 'Not executed: the gateway refused the call'
  }

  return toolRan(run.result.execution) ? 'Authorised, and the gateway ran the tool once' : 'The gateway did not run the tool'
}

function trail(run: ScenarioRun): TrailStep[] {
  switch (run.kind) {
    case 'input':
      return inputTrail(run.result.analysis)
    case 'tool':
      return toolTrail(run.result.execution)
    case 'replay':
      return [...toolTrail(run.first.execution), replayStep(run.second)]
    case 'approval':
      return approvalTrail(run)
  }
}

function Trail({ steps, kind }: { steps: readonly TrailStep[]; kind: 'input' | 'agent' }) {
  return (
    <section aria-labelledby="trail-heading" className="space-y-3">
      <h3 id="trail-heading" className="text-sm font-semibold text-foreground">
        {kind === 'input' ? 'Input security: what each stage did' : 'Agent security: what each stage did'}
      </h3>
      <ol className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {steps.map((step, index) => (
          <li key={`${step.label}-${index}`} className={`rounded-md border border-l-4 border-border bg-background px-3 py-2 ${stepClass[step.tone]}`}>
            <span className="block text-xs font-semibold text-muted">
              {index + 1}. {step.label}
            </span>
            <span className="block text-sm text-foreground">{step.value}</span>
          </li>
        ))}
      </ol>
    </section>
  )
}

const comparisonText: Record<IntentComparison, string> = {
  matches: 'The API’s result matches.',
  differs: 'The API returned something else. The result above is the API’s, whatever the scenario intended.',
  unknown: 'The API’s decision is not one this console recognises, so it cannot be compared.',
}

function Intent({ scenario, comparison }: { scenario: AttackScenario; comparison: IntentComparison }) {
  return (
    <p className="text-sm text-muted">
      Written to show: {describeIntent(scenario)}. {comparisonText[comparison]}
    </p>
  )
}

function InputEvidence({ result }: { result: FirewallAnalysisResult }) {
  const findings = Array.isArray(result.analysis.findings) ? result.analysis.findings.map(presentFinding) : []
  return (
    <>
      <FindingsSection findings={findings} />
      <Identifiers>
        <Identifier term="Security event ID" value={result.analysis.securityEventId} />
        <Identifier term="Correlation ID" value={result.correlationId} />
      </Identifiers>
    </>
  )
}

function GatewayEvidence({ result, heading = 'What the gateway reported' }: { result: ToolExecutionResult; heading?: string }) {
  const { execution } = result
  const reason = presentAgentActionReason(execution.authorizationReason)
  const outcome = presentToolOutcome(execution.outcome)
  const ran = toolRan(execution)
  const text = resultText(execution)

  return (
    <section aria-labelledby={`${idOf(heading)}-heading`} className="space-y-3">
      <h3 id={`${idOf(heading)}-heading`} className="text-sm font-semibold text-foreground">
        {heading}
      </h3>
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[auto_minmax(0,1fr)]">
        <Fact term="Authorization">
          <span className="font-medium">{reason.label}.</span> <span className="text-muted">{reason.explanation}</span>
        </Fact>
        <Fact term="Gateway outcome">
          <span className="font-medium">{outcome.label}.</span> <span className="text-muted">{outcome.explanation}</span>
        </Fact>
        {ran && (
          <Fact term="Tool result">
            {text ? <span>{text}</span> : <span className="text-muted">The dataset has nothing on this topic.</span>}
          </Fact>
        )}
      </dl>
      <Identifiers>
        <Identifier term="Security event ID" value={execution.securityEventId} />
        <Identifier term="Correlation ID" value={result.correlationId} />
        {typeof execution.executionId === 'string' && <Identifier term="Execution ID (audit only, not a credential)" value={execution.executionId} />}
      </Identifiers>
    </section>
  )
}

function ReplayEvidence({ run }: { run: Extract<ScenarioRun, { kind: 'replay' }> }) {
  const { second } = run
  return (
    <section aria-labelledby="replay-heading" className="space-y-3">
      <h3 id="replay-heading" className="text-sm font-semibold text-foreground">
        Second request: presenting the execution ID
      </h3>
      {second.status === 'rejected' && (
        <>
          <p className="text-sm text-foreground">
            {second.contractRejection
              ? 'The API rejected the request before authorising, deciding or running anything: a request cannot carry an execution authorization. Grants are issued and checked inside AgentShield and never reach the client.'
              : 'The API rejected the request, so nothing was decided or run.'}
          </p>
          <Identifiers>
            <Identifier term="HTTP status" value={String(second.httpStatus)} />
            {second.correlationId && <Identifier term="Correlation ID" value={second.correlationId} />}
          </Identifiers>
        </>
      )}
      {second.status === 'accepted' && <GatewayEvidence result={second.result} heading="The API accepted the second request" />}
      {second.status === 'failed' && <FailedReplay error={second.error} />}
    </section>
  )
}

/**
 * The held call: while it waits, the pending approval with the person's two choices; once decided, what the approval
 * endpoint said and what the gateway did when the agent presented the approval with the same call.
 */
function ApprovalEvidence({ run, controls }: { run: ApprovalRun; controls: ApprovalControls | undefined }) {
  const held = run.held.execution
  const reason = presentAgentActionReason(held.authorizationReason)
  const pending = held.outcome === 'HeldForReview' && typeof held.approvalId === 'string'
  const decision = run.decision === undefined ? undefined : presentApprovalDecision(run.decision)
  const input = presentRunDecision(run.analysis.analysis.decision)

  return (
    <>
      <section aria-labelledby="approval-heading" className="space-y-3 rounded-lg border border-warning/30 bg-warning/10 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <h3 id="approval-heading" className="text-sm font-semibold text-foreground">
            {decision === undefined ? 'Pending approval' : 'A person decided'}
          </h3>
          {decision !== undefined && <Badge tone={decision.tone}>{decision.label}</Badge>}
        </div>
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_minmax(0,1fr)]">
          <Fact term="Agent">research-agent (from the API key)</Fact>
          <Fact term="Tool and action">
            <code className="font-mono text-xs">knowledge.lookup</code>
          </Fact>
          <Fact term="Risk">{presentRunRisk(held.riskLevel).label}</Fact>
          <Fact term="Reason">{reason.explanation}</Fact>
          <Fact term="Input">
            {input.known
              ? `The firewall decided ${input.label}; the gateway used its own record of that, so the agent’s claim that the input was allowed changed nothing.`
              : 'The firewall’s decision was not recognised.'}
          </Fact>
        </dl>
        {decision === undefined && pending && controls !== undefined && (
          <div className="flex flex-wrap items-center gap-2 border-t border-warning/30 pt-3">
            <Button onClick={() => controls.onDecide(true)} disabled={controls.deciding}>
              {controls.deciding && <SpinnerIcon />}
              Approve
            </Button>
            <Button variant="secondary" onClick={() => controls.onDecide(false)} disabled={controls.deciding}>
              Deny
            </Button>
            <p className="text-xs text-muted">Approving lets the agent run exactly this call once. Then the console presents it to the gateway as the agent.</p>
          </div>
        )}
        {controls?.error !== undefined && controls.error !== null && <DecisionError error={controls.error} />}
      </section>
      {run.final !== undefined && <GatewayEvidence result={run.final} heading="The agent presented the approval with the same call" />}
      {run.final === undefined && (
        <Identifiers>
          <Identifier term="Input security event (firewall)" value={run.analysis.analysis.securityEventId} />
          <Identifier term="Held request’s security event" value={held.securityEventId} />
          <Identifier term="Approval ID" value={held.approvalId} />
          <Identifier term="Correlation ID (one trace for both)" value={run.held.correlationId} />
        </Identifiers>
      )}
    </>
  )
}

function DecisionError({ error }: { error: unknown }) {
  const presentation = presentApprovalError(error)
  return (
    <div role="alert" className="flex gap-3 rounded-md border border-danger/30 bg-surface p-3 text-sm">
      <ErrorIcon className="mt-0.5 size-5 shrink-0 text-danger" />
      <div className="min-w-0 space-y-1">
        <p className="font-semibold text-foreground">{presentation.title}</p>
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

function FailedReplay({ error }: { error: unknown }) {
  const presentation = presentToolGatewayError(error)
  return (
    <div className="flex gap-3 rounded-lg border border-warning/30 bg-warning/10 p-4">
      <ErrorIcon className="mt-0.5 size-5 shrink-0 text-warning" />
      <div className="min-w-0 space-y-1 text-sm">
        <p className="font-semibold text-foreground">{presentation.title}</p>
        <p className="text-foreground">{presentation.description} The first request’s result above stands.</p>
        {presentation.reference && (
          <p className="text-xs text-muted">
            Reference <code className="font-mono break-all">{presentation.reference}</code>
          </p>
        )}
      </div>
    </div>
  )
}

function idOf(text: string): string {
  return text.toLowerCase().replace(/[^a-z]+/g, '-').replace(/^-|-$/g, '')
}

function Identifiers({ children }: { children: ReactNode }) {
  return <dl className="grid gap-x-6 gap-y-2 rounded-md border border-border bg-background px-3 py-2 text-xs sm:grid-cols-[auto_minmax(0,1fr)]">{children}</dl>
}

/** An identifier from the response, shown as text; anything that is not a string is not rendered. */
function Identifier({ term, value }: { term: string; value: unknown }) {
  return (
    <div className="space-y-0.5 sm:contents">
      <dt className="text-muted">{term}</dt>
      <dd className="min-w-0">
        {typeof value === 'string' && value !== '' ? <code className="font-mono break-all text-foreground">{value}</code> : <span className="text-muted">Not reported</span>}
      </dd>
    </div>
  )
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5 sm:contents">
      <dt className="text-muted">{term}</dt>
      <dd className="min-w-0 text-foreground">{children}</dd>
    </div>
  )
}
