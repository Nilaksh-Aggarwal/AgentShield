import { ErrorIcon } from '@/shared/components/ui'
import { presentAnalysisError } from '../model'

interface AnalysisErrorCardProps {
  error: unknown
  /**
   * Announce the card as an alert. Off when the same failure is already announced elsewhere (field-level validation
   * messages next to the text box), so a screen reader does not read two alerts at once.
   */
  announce?: boolean
}

/** A failed analysis: what happened, what to do, and a reference for support. Never shows raw server text. */
export function AnalysisErrorCard({ error, announce = true }: AnalysisErrorCardProps) {
  const presentation = presentAnalysisError(error)

  return (
    <section
      role={announce ? 'alert' : undefined}
      aria-labelledby="analysis-error-heading"
      className="flex gap-3 rounded-lg border border-danger/30 bg-danger/10 p-4 sm:p-6"
    >
      <ErrorIcon className="mt-0.5 size-5 text-danger" />
      <div className="min-w-0 space-y-1.5">
        <h2 id="analysis-error-heading" className="font-semibold text-danger">
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
