import { Badge, InfoIcon, SectionHeader } from '@/shared/components/ui'
import { findingSourceLabels, type FindingPresentation, type FindingSource } from '../model'
import { FindingCard } from './FindingCard'
import { sourceStyle } from './sourceStyle'

const sourceMeaning: Record<FindingSource, string> = {
  rules: 'AgentShield’s deterministic detection rules.',
  ai: 'The optional AI analysis: one more signal, never the decision.',
  system: 'A safeguard: the input could not be fully checked, so it is held for review.',
}

export function FindingsSection({ findings }: { findings: readonly FindingPresentation[] }) {
  const sources = (['rules', 'ai', 'system'] as const).filter((source) => findings.some((finding) => finding.source === source))
  const showsConfidence = findings.some((finding) => finding.confidence !== null)

  return (
    <section className="space-y-4" aria-labelledby="findings-heading">
      <SectionHeader
        as="h3"
        id="findings-heading"
        title={
          <>
            Findings <span className="font-normal text-muted">({findings.length})</span>
          </>
        }
        description={findings.length > 0 ? 'What the checks found, most severe first.' : undefined}
      />

      {findings.length === 0 ? (
        <p className="rounded-lg border border-border bg-surface px-4 py-3 text-sm text-muted">
          No findings: none of the checks reported anything for this input.
        </p>
      ) : (
        <>
          <dl className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-muted">
            {sources.map((source) => {
              const { tone, Icon } = sourceStyle[source]
              return (
                <div key={source} className="flex items-center gap-2">
                  <dt>
                    <Badge tone={tone}>
                      <Icon className="size-3.5" />
                      {findingSourceLabels[source]}
                    </Badge>
                  </dt>
                  <dd>{sourceMeaning[source]}</dd>
                </div>
              )
            })}
          </dl>
          <ul className="grid gap-3">
            {findings.map((finding, index) => (
              <li key={`${finding.category}:${finding.code}`}>
                <FindingCard finding={finding} headingId={`finding-${index}`} />
              </li>
            ))}
          </ul>
          {showsConfidence && (
            <p className="flex gap-2 text-xs text-muted">
              <InfoIcon className="mt-px size-3.5" />
              Confidence is an estimate set by a rule’s author or reported by the AI model, not a measured probability.
              It does not change the risk score.
            </p>
          )}
        </>
      )}
    </section>
  )
}
