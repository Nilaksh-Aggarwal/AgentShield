import { useState } from 'react'
import { useSearchParams } from 'react-router'
import { presentToolGatewayError } from '@/features/agents'
import { presentAnalysisError } from '@/features/firewall'
import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { ArrowRightIcon, ButtonLink, Card, EmptyState, ErrorIcon, FlagIcon, InfoIcon, SpinnerIcon } from '@/shared/components/ui'
import type { ApprovalRun, ScenarioRun } from '../api/runScenario'
import { useApprovalDecision } from '../hooks/useApprovalDecision'
import { useScenarioRun } from '../hooks/useScenarioRun'
import { presentApprovalDecision, runDecision, runExecutedTool } from '../model/evidence'
import type { SessionRun } from '../model/report'
import { agentScenarios, defaultScenario, findScenario, inputScenarios, type AttackScenario } from '../model/scenarios'
import { AttackLabLimitations } from './AttackLabLimitations'
import { RunResult } from './RunResult'
import { ScenarioBrief } from './ScenarioBrief'
import { GroupSwitch, ScenarioList, type ScenarioGroup } from './ScenarioPicker'
import { SessionRuns } from './SessionRuns'

const firstScenario: Readonly<Record<ScenarioGroup, AttackScenario>> = {
  input: inputScenarios[0] ?? defaultScenario,
  agent: agentScenarios[0] ?? defaultScenario,
}

const groupText: Readonly<Record<ScenarioGroup, { heading: string; description: string }>> = {
  input: {
    heading: 'Input security scenarios',
    description: 'Each input goes to the firewall, which detects, scores and decides. No tool is involved.',
  },
  agent: {
    heading: 'Agent security scenarios',
    description: 'Each call goes to the tool gateway, which authorises it and runs the tool only on Allow, or after a person approves a call it held.',
  },
}

/**
 * The Attack Lab: a thin demonstration layer over the real API. Each scenario is an ordinary request to the firewall or the
 * tool gateway, and the page shows what the API returned. It has no security logic of its own: it never decides,
 * scores, authorises or runs anything, and it never shows a scenario's intent in place of the API's answer.
 */
export function AttackLabPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [runs, setRuns] = useState<SessionRun[]>([])
  const [announcement, setAnnouncement] = useState('')
  const scenarioRun = useScenarioRun()
  const approvalDecision = useApprovalDecision()

  // The URL only selects from the built-in catalogue: an unknown ID falls back to the first scenario and is never shown or sent.
  const selected = findScenario(searchParams.get('scenario') ?? undefined) ?? firstScenario.input
  const group: ScenarioGroup = selected.kind === 'input' ? 'input' : 'agent'
  const scenarios = group === 'input' ? inputScenarios : agentScenarios

  const runningScenario = scenarioRun.isPending ? scenarioRun.variables : undefined
  const forSelected = scenarioRun.variables?.id === selected.id
  const latest = runs.findLast((entry) => entry.scenario.id === selected.id)

  function select(scenario: AttackScenario) {
    setSearchParams({ scenario: scenario.id }, { replace: true })
  }

  function changeGroup(next: ScenarioGroup) {
    if (next !== group) {
      select(firstScenario[next])
    }
  }

  function run() {
    const scenario = selected
    approvalDecision.reset()
    scenarioRun.mutate(scenario, {
      onSuccess: (result) => {
        setRuns((previous) => [...previous, { scenario, run: result }])
        setAnnouncement(announce(scenario, result))
      },
    })
  }

  // The approval scenario's second phase: a person decides the held call shown, then the agent presents the approval.
  function decide(approve: boolean) {
    const target = latest
    if (target === undefined || target.run.kind !== 'approval' || target.scenario.kind !== 'approval') {
      return
    }

    const scenario = target.scenario
    approvalDecision.mutate(
      { scenario, run: target.run, approve },
      {
        onSuccess: (decided: ApprovalRun) => {
          setRuns((previous) => previous.map((entry) => (entry === target ? { scenario, run: decided } : entry)))
          setAnnouncement(announce(scenario, decided))
        },
      },
    )
  }

  // Announced by screen readers; the visible page carries the same information.
  let status = announcement
  if (runningScenario) {
    status = `Running ${runningScenario.id}, ${runningScenario.title}, against the live API…`
  } else if (approvalDecision.isPending) {
    status = 'Sending the decision to AgentShield, then presenting the approval as the agent…'
  }

  return (
    <div className="space-y-8">
      <DocumentTitle title="Attack Lab" />
      <PageHeader
        eyebrow="Live API · Synthetic scenarios"
        title="Attack Lab"
        description={
          <>
            <p className="text-foreground">Test AgentShield against real security scenarios.</p>
            <p>
              Pick an attack, run it, and see what AgentShield detected, how it decided and, for agent tool calls, whether the
              tool ran. Every result is the live API’s answer, and every run is recorded in Activity.
            </p>
          </>
        }
        actions={
          <>
            <ButtonLink to="/activity" variant="secondary">
              Open Activity
              <ArrowRightIcon />
            </ButtonLink>
            <ButtonLink to="/analyze" variant="secondary">
              Analyze your own input
            </ButtonLink>
          </>
        }
      />

      <LabNotice />

      <section aria-label="Scenarios" className="space-y-6">
        <GroupSwitch group={group} onChange={(next) => changeGroup(next)} />

        <div className="grid gap-6 lg:grid-cols-[18rem_minmax(0,1fr)] lg:items-start">
          <div className="space-y-3">
            <div className="space-y-1">
              <h2 id="list-heading" className="text-sm font-semibold text-foreground">
                {groupText[group].heading}
              </h2>
              <p className="text-xs text-muted">{groupText[group].description}</p>
            </div>
            <ScenarioList label={groupText[group].heading} scenarios={scenarios} selectedId={selected.id} onSelect={select} />
          </div>

          <div className="min-w-0 space-y-6">
            <ScenarioBrief
              scenario={selected}
              onRun={run}
              running={runningScenario?.id === selected.id}
              busy={scenarioRun.isPending}
              hasRun={latest !== undefined}
            />

            <div aria-busy={runningScenario?.id === selected.id}>
              {forSelected && scenarioRun.isPending ? (
                // Honest progress: the API answers only after every stage has run, so no stage is shown as done.
                <Card className="space-y-4" aria-hidden="true">
                  <p className="flex items-center gap-3 font-medium text-foreground">
                    <SpinnerIcon className="size-5 text-primary" />
                    Sending the scenario to the live API…
                  </p>
                  <div className="space-y-2 motion-safe:animate-pulse">
                    <div className="h-3 w-2/3 rounded bg-border" />
                    <div className="h-3 w-1/2 rounded bg-border" />
                  </div>
                </Card>
              ) : forSelected && scenarioRun.isError ? (
                <RunErrorCard scenario={selected} error={scenarioRun.error} />
              ) : latest ? (
                <RunResult
                  scenario={latest.scenario}
                  run={latest.run}
                  approval={
                    latest.run.kind === 'approval'
                      ? { onDecide: decide, deciding: approvalDecision.isPending, error: approvalDecision.isError ? approvalDecision.error : undefined }
                      : undefined
                  }
                />
              ) : (
                <EmptyState
                  icon={<FlagIcon className="size-5" />}
                  title="Not run yet"
                  description={<p>Press Run scenario to send it to the live API. The result shown will be the API’s answer.</p>}
                />
              )}
            </div>
          </div>
        </div>
      </section>

      <SessionRuns runs={runs} />
      <AttackLabLimitations />

      <p role="status" className="sr-only">
        {status}
      </p>
    </div>
  )
}

function announce(scenario: AttackScenario, run: ScenarioRun): string {
  if (run.kind === 'approval') {
    if (run.decision === undefined) {
      return `${scenario.id}, ${scenario.title}: decision ${runDecision(run).label}. Pending a person’s approval; nothing runs until then.`
    }

    return `${scenario.id}, ${scenario.title}: ${presentApprovalDecision(run.decision).label}. ${runExecutedTool(run) ? 'The tool ran once.' : 'The tool did not run.'}`
  }

  const decision = runDecision(run)
  const tool = run.kind === 'input' ? 'No tool involved.' : runExecutedTool(run) ? 'The tool ran.' : 'The tool did not run.'
  const replay = run.kind === 'replay' ? (run.second.status === 'rejected' ? ' The replay was rejected.' : ' The replay was not rejected.') : ''
  return `${scenario.id}, ${scenario.title}: decision ${decision.label}. ${tool}${replay}`
}

function LabNotice() {
  return (
    <p className="flex gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-sm text-foreground shadow-xs">
      <InfoIcon className="mt-0.5 size-4 shrink-0 text-muted" />
      <span>
        The console sends each scenario as an ordinary API request, as the public Development client acting as the demo research
        agent, and decides nothing itself. The scenarios are synthetic example data, written for the deterministic rules: no AI
        provider is needed.
      </span>
    </p>
  )
}

function RunErrorCard({ scenario, error }: { scenario: AttackScenario; error: unknown }) {
  const presentation = scenario.kind === 'input' ? presentAnalysisError(error) : presentToolGatewayError(error)

  return (
    <section role="alert" aria-labelledby="run-error-heading" className="flex gap-3 rounded-lg border border-danger/30 bg-danger/10 p-4 sm:p-6">
      <ErrorIcon className="mt-0.5 size-5 shrink-0 text-danger" />
      <div className="min-w-0 space-y-1.5">
        <h2 id="run-error-heading" className="font-semibold text-danger">
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
