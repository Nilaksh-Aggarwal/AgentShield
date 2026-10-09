import { AnalyzeIcon, ArrowRightIcon, ButtonLink } from '@/shared/components/ui'

export function TryItCallout() {
  return (
    <section
      aria-labelledby="try-it-heading"
      className="flex flex-col gap-4 rounded-lg border border-primary/30 bg-primary/10 p-6 sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-full bg-surface text-primary" aria-hidden="true">
          <AnalyzeIcon className="size-5" />
        </span>
        <div className="space-y-1">
          <h2 id="try-it-heading" className="text-lg font-semibold tracking-tight text-foreground">
            See AgentShield in action
          </h2>
          <p className="text-sm text-foreground">
            Submit an input, or try one of the examples, and see how the security pipeline evaluates it.
          </p>
        </div>
      </div>
      <ButtonLink to="/analyze" className="shrink-0">
        Open Analyzer
        <ArrowRightIcon />
      </ButtonLink>
    </section>
  )
}
