import { ErrorIcon } from '@/shared/components/ui'
import { presentActivityError } from '../model'

/** A failed read of the history: what happened and a reference for support. Never shows raw server text. */
export function ActivityErrorCard({ error }: { error: unknown }) {
  const presentation = presentActivityError(error)

  return (
    <section role="alert" aria-labelledby="activity-error-heading" className="flex gap-3 rounded-lg border border-danger/30 bg-danger/10 p-4 sm:p-6">
      <ErrorIcon className="mt-0.5 size-5 text-danger" />
      <div className="min-w-0 space-y-1.5">
        <h2 id="activity-error-heading" className="font-semibold text-danger">
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
