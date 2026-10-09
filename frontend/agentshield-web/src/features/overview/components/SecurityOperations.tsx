import { presentActivityError, useActivitySummary, type ActivitySummary } from '@/features/activity'
import { ArrowRightIcon, ButtonLink, Card, ErrorIcon, FlagIcon, SectionHeader, SpinnerIcon, type Tone } from '@/shared/components/ui'

/** A count as the API sent it, only when it is one: a non-negative integer. Anything else is not shown as a number. */
function count(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : undefined
}

const timeFormat = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

function time(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : timeFormat.format(date)
}

// Class strings are written out in full so Tailwind can find them when scanning the source.
const accentClass: Record<Tone, string> = {
  neutral: 'border-t-border',
  info: 'border-t-primary',
  success: 'border-t-success',
  warning: 'border-t-warning',
  danger: 'border-t-danger',
  critical: 'border-t-danger',
}

/**
 * Security operations: counts over the API's activity history, read live. The history is in memory and per process, so
 * the counts are labelled as exactly that: never a period, a trend or a total the API does not hold. While loading or after
 * a failure no number is shown, never a zero.
 */
export function SecurityOperations() {
  const summary = useActivitySummary()

  return (
    <section aria-labelledby="operations-heading" className="space-y-6">
      <SectionHeader
        id="operations-heading"
        eyebrow="Security operations"
        title="What this API process has decided"
        description="Live counts from the activity history: in memory, in this API process only, at most its last 1,000 events, cleared when it restarts. Every client’s requests are counted, Attack Lab runs included."
        actions={
          <ButtonLink to="/activity" variant="secondary">
            Open Activity
            <ArrowRightIcon />
          </ButtonLink>
        }
      />
      {summary.isPending ? (
        <Card aria-busy="true">
          <p className="flex items-center gap-3 text-sm text-muted">
            <SpinnerIcon className="size-4 text-primary" />
            Loading the counts…
          </p>
        </Card>
      ) : summary.isError ? (
        <SummaryError error={summary.error} />
      ) : (
        <Counts summary={summary.data} />
      )}
    </section>
  )
}

function Counts({ summary }: { summary: ActivitySummary }) {
  const total = count(summary.totalCount)
  if (total === 0) {
    return (
      <div className="flex flex-col items-start gap-3 rounded-lg border border-dashed border-border bg-surface p-6 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <h3 className="font-semibold text-foreground">No security events yet</h3>
          <p className="text-sm text-muted">This API process has not decided anything since it started. Run an attack to see the counts move.</p>
        </div>
        <ButtonLink to="/attack-lab" className="shrink-0">
          <FlagIcon />
          Open the Attack Lab
        </ButtonLink>
      </div>
    )
  }

  const oldest = time(summary.oldestOccurredAt)
  const newest = time(summary.newestOccurredAt)
  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Decisions">
        <Stat label="Events held" value={total} tone="info" />
        <Stat label="Allowed" value={count(summary.decisions?.allow)} tone="success" />
        <Stat label="Held for review" value={count(summary.decisions?.review)} tone="warning" />
        <Stat label="Blocked" value={count(summary.decisions?.block)} tone="danger" />
      </dl>
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Kinds of event">
        <Stat label="Inputs analysed" value={count(summary.kinds?.inputAnalysis)} tone="neutral" />
        <Stat label="Agent actions decided" value={count(summary.kinds?.agentActionAuthorization)} tone="neutral" />
        <Stat label="Tool calls through the gateway" value={count(summary.kinds?.toolExecution)} tone="neutral" />
        <Stat label="Tools that ran" value={count(summary.toolsExecuted)} tone="neutral" />
      </dl>
      {oldest && newest && (
        <p className="text-xs text-muted">
          Oldest event held: {oldest}. Newest: {newest}.
        </p>
      )}
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: number | undefined; tone: Tone }) {
  return (
    <div className={`rounded-lg border border-t-4 border-border bg-surface px-4 py-3 shadow-xs ${accentClass[tone]}`}>
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="text-2xl font-semibold text-foreground tabular-nums">{value ?? <span className="text-base font-medium text-muted">Not reported</span>}</dd>
    </div>
  )
}

function SummaryError({ error }: { error: unknown }) {
  const presentation = presentActivityError(error)
  return (
    <div className="flex gap-3 rounded-lg border border-border bg-surface p-4 shadow-xs">
      <ErrorIcon className="mt-0.5 size-5 shrink-0 text-danger" />
      <div className="min-w-0 space-y-1 text-sm">
        <h3 className="font-semibold text-foreground">{presentation.title}</h3>
        <p className="text-foreground">{presentation.description} The counts couldn’t be loaded, so none are shown.</p>
        {presentation.reference && (
          <p className="text-xs text-muted">
            Reference <code className="font-mono break-all">{presentation.reference}</code>
          </p>
        )}
      </div>
    </div>
  )
}
