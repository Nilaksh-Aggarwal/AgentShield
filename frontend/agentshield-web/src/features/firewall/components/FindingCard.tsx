import { Badge, type Tone } from '@/shared/components/ui'
import type { FindingPresentation } from '../model'
import { sourceStyle } from './sourceStyle'

// Class strings are written out in full so Tailwind can find them when scanning the source.
const accentClass: Record<Tone, string> = {
  neutral: 'border-l-border',
  info: 'border-l-primary',
  success: 'border-l-success',
  warning: 'border-l-warning',
  danger: 'border-l-danger',
  critical: 'border-l-danger',
}

/** One finding in plain language. Never shows rule IDs, patterns, decoded or hidden content. */
export function FindingCard({ finding, headingId }: { finding: FindingPresentation; headingId: string }) {
  const source = sourceStyle[finding.source]

  return (
    <article
      aria-labelledby={headingId}
      className={`flex h-full flex-col gap-3 rounded-lg border border-l-4 border-border bg-surface p-4 ${accentClass[finding.severity.tone]}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={finding.severity.tone}>{finding.severity.label} severity</Badge>
        <Badge tone={source.tone}>
          <source.Icon className="size-3.5" />
          {finding.sourceLabel}
        </Badge>
      </div>
      <div className="space-y-1">
        <h4 id={headingId} className="font-semibold text-foreground">
          {finding.title}
        </h4>
        <p className="text-sm text-foreground">{finding.description}</p>
        {finding.confidence && (
          <p className="text-xs text-muted">
            {finding.confidence.label}: <span className="font-medium text-foreground">{finding.confidence.level}</span>
          </p>
        )}
      </div>
      <div className="mt-auto rounded-md bg-background px-3 py-2">
        <p className="text-xs font-semibold tracking-wide text-muted uppercase">Recommended action</p>
        <p className="mt-0.5 text-sm text-foreground">{finding.recommendedAction}</p>
      </div>
    </article>
  )
}
