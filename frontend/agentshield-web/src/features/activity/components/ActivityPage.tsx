import { useState } from 'react'
import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { ActivityIcon, ArrowRightIcon, Button, ButtonLink, Card, CardHeader, EmptyState, SpinnerIcon } from '@/shared/components/ui'
import type { DecisionFilter } from '../api/listActivity'
import { useSecurityActivity } from '../hooks/useSecurityActivity'
import { ActivityErrorCard } from './ActivityErrorCard'
import { ActivityFilters } from './ActivityFilters'
import { ActivityList } from './ActivityList'
import { ActivityPagination } from './ActivityPagination'

const emptyFilterTitles: Readonly<Record<DecisionFilter, string>> = {
  all: 'No activity yet',
  Allow: 'No allowed inputs',
  Review: 'No inputs held for review',
  Block: 'No blocked inputs',
}

/**
 * The security activity history: recent decisions as security metadata, filterable by decision and paged. It shows only
 * what the API returns for each event, and the API returns no analysed text, so there is none to show.
 */
export function ActivityPage() {
  const [decision, setDecision] = useState<DecisionFilter>('all')
  const [page, setPage] = useState(1)
  const activity = useSecurityActivity({ decision, page })
  const data = activity.data

  function chooseFilter(value: DecisionFilter) {
    setDecision(value)
    setPage(1)
  }

  const status = data
    ? `Showing ${data.items.length} of ${data.totalCount} ${data.totalCount === 1 ? 'event' : 'events'}, page ${data.page} of ${Math.max(data.totalPages, 1)}.`
    : activity.isPending
      ? 'Loading activity…'
      : ''

  return (
    <section className="space-y-6" aria-labelledby="activity-heading">
      <DocumentTitle title="Activity" />
      <PageHeader
        id="activity-heading"
        eyebrow="Security operations"
        title="Security activity"
        description={<p>What AgentShield decided recently, newest first. Security metadata only: the analysed text is never stored or shown.</p>}
        actions={
          <Button variant="secondary" onClick={() => void activity.refetch()} disabled={activity.isFetching}>
            {activity.isFetching && <SpinnerIcon />}
            Refresh
          </Button>
        }
      />

      <ActivityFilters value={decision} onChange={chooseFilter} />

      <p role="status" className="sr-only">
        {status}
      </p>

      {activity.isError && <ActivityErrorCard error={activity.error} />}

      {activity.isPending && (
        <Card className="flex items-center gap-3 text-sm text-muted">
          <SpinnerIcon />
          Loading activity…
        </Card>
      )}

      {data && data.totalCount === 0 && (
        <EmptyState
          icon={<ActivityIcon className="size-5" />}
          title={emptyFilterTitles[decision]}
          description={
            decision === 'all' ? (
              <p>Each input AgentShield analyses, and each agent action it is asked to authorize, appears here with its decision and risk. The history is kept in server memory, so it starts empty after a restart.</p>
            ) : (
              <p>None of the recent events has this decision.</p>
            )
          }
          action={
            decision === 'all' ? (
              <ButtonLink to="/analyze" variant="secondary">
                Analyze an input
                <ArrowRightIcon />
              </ButtonLink>
            ) : (
              <Button variant="secondary" onClick={() => chooseFilter('all')}>
                Show all activity
              </Button>
            )
          }
        />
      )}

      {data && data.totalCount > 0 && (
        <Card as="section" padding="none" aria-labelledby="events-heading" aria-busy={activity.isPlaceholderData}>
          <CardHeader
            id="events-heading"
            title="Recent events"
            description={`${data.totalCount} ${data.totalCount === 1 ? 'event' : 'events'}${decision === 'all' ? '' : ' with this decision'}`}
          />
          {data.items.length > 0 ? (
            <ActivityList items={data.items} />
          ) : (
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-6 text-sm text-muted sm:px-6">
              <p>This page has no events: the history has changed since it was opened.</p>
              <Button variant="secondary" onClick={() => setPage(1)}>
                Back to the first page
              </Button>
            </div>
          )}
          <ActivityPagination page={data.page} totalPages={data.totalPages} onPage={setPage} busy={activity.isPlaceholderData} />
        </Card>
      )}

      <AboutActivity />
    </section>
  )
}

function AboutActivity() {
  return (
    <Card as="section" aria-labelledby="about-activity-heading" className="space-y-3">
      <h2 id="about-activity-heading" className="text-sm font-semibold text-foreground">
        About this history
      </h2>
      <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted">
        <li>
          <span className="font-medium text-foreground">Metadata only.</span> Each entry holds the decision, the risk score and
          level, the kinds of findings, whether AI-assisted analysis completed and the event’s trace IDs. The analysed text,
          anything decoded from it, rule details and AI provider responses are never stored or shown.
        </li>
        <li>
          <span className="font-medium text-foreground">Recent events, in server memory.</span> Only the most recent events are
          kept. The history starts empty when the server restarts and is not shared between server instances; the audit log
          remains the record of every decision.
        </li>
        <li>
          <span className="font-medium text-foreground">“Incomplete” AI analysis.</span> When an expected AI analysis does not
          complete, the input is held for review. Why it did not complete is kept in the audit log only, so this view cannot be
          used to probe the analyser.
        </li>
        <li>
          <span className="font-medium text-foreground">Agent actions.</span> An agent action shows the decision, the action’s risk
          level, the reason and the agent, tool, action and capability AgentShield recognised. A name it does not recognise is
          shown as unknown. Tool arguments are never received, so they cannot be shown.
        </li>
        <li>
          <span className="font-medium text-foreground">Every client’s analyses.</span> Reading this history needs its own
          permission, separate from submitting inputs.
        </li>
      </ul>
    </Card>
  )
}
