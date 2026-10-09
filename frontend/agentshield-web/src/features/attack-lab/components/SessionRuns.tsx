import { Badge, Button, Card, CardHeader } from '@/shared/components/ui'
import type { ScenarioRun } from '../api/runScenario'
import { runDecision, runExecutedTool } from '../model/evidence'
import { buildSecurityReport, type SessionRun } from '../model/report'

function correlationIdOf(run: ScenarioRun): unknown {
  switch (run.kind) {
    case 'replay':
      return run.first.correlationId
    case 'approval':
      return (run.final ?? run.held).correlationId
    default:
      return run.result.correlationId
  }
}

/** Saves the report as a file. Browser glue only: nothing is sent anywhere. */
function download(runs: readonly SessionRun[]) {
  const now = new Date()
  const report = buildSecurityReport(runs, now)
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `agentshield-attack-lab-${now.toISOString().replace(/[:.]/g, '-')}.json`
  link.click()
  // Released after the click has started the download.
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

/** This visit's runs, newest first, and the metadata-only export. Kept on this page only; leaving it clears them. */
export function SessionRuns({ runs }: { runs: readonly SessionRun[] }) {
  return (
    <Card as="section" padding="none" aria-labelledby="session-heading">
      <CardHeader
        id="session-heading"
        title={
          <>
            This visit’s runs <span className="font-normal text-muted">({runs.length})</span>
          </>
        }
        description="Kept on this page only, cleared when you leave it. The export holds metadata only: scenario IDs, decisions, outcomes, finding codes and identifiers; never inputs, tool arguments or tool results."
        actions={
          <Button variant="secondary" onClick={() => download(runs)} disabled={runs.length === 0}>
            Export security report (JSON)
          </Button>
        }
      />
      {runs.length === 0 ? (
        <p className="px-4 py-4 text-sm text-muted sm:px-6">No scenario has run yet.</p>
      ) : (
        <ol className="divide-y divide-border" aria-label="Runs, newest first">
          {[...runs].reverse().map(({ scenario, run }, index) => {
            const decision = runDecision(run)
            const correlationId = correlationIdOf(run)
            return (
              <li key={runs.length - index} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2 text-sm sm:px-6">
                <span className="font-mono text-xs font-semibold text-muted">{scenario.id}</span>{' '}
                <span className="min-w-0 flex-1 font-medium text-foreground">{scenario.title}</span>
                <span className="sr-only">: decision </span>
                <Badge tone={decision.tone}>{decision.label}</Badge>
                <span className="sr-only">, </span>
                <span className="text-xs text-muted">
                  {run.kind === 'input'
                    ? 'No tool involved'
                    : run.kind === 'approval' && run.decision === undefined
                      ? 'Pending approval'
                      : runExecutedTool(run)
                        ? 'Tool ran'
                        : 'Tool did not run'}
                </span>
                {typeof correlationId === 'string' && (
                  <span className="w-full text-xs text-muted sm:w-auto">
                    Correlation ID <code className="font-mono break-all">{correlationId}</code>
                  </span>
                )}
              </li>
            )
          })}
        </ol>
      )}
    </Card>
  )
}
