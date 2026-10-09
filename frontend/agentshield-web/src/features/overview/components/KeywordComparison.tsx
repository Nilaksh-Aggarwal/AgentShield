import { ArrowRightIcon, Card, SectionHeader } from '@/shared/components/ui'

// Disguises the obfuscation check undoes today; samples are single harmless words, never payloads.
const disguises = [
  { technique: 'Spaced-out letters', sample: 'i g n o r e', filter: 'No keyword to match', agentShield: 'Joins the letters, then checks again' },
  { technique: 'Character substitutions', sample: '1gn0r3', filter: 'No keyword to match', agentShield: 'Reads the substitutes as letters, then checks again' },
  {
    technique: 'Look-alike letters',
    sample: 'Cyrillic “о” instead of Latin “o”',
    filter: 'A different word',
    agentShield: 'Maps look-alikes to the letters they imitate',
  },
  {
    technique: 'Encoding',
    sample: 'Base64, URL encoding, HTML entities',
    filter: 'Random-looking text',
    agentShield: 'Decodes (up to two layers), then checks again',
  },
  {
    technique: 'Invisible characters',
    sample: 'Unicode tag characters, variation selectors',
    filter: 'Nothing visible at all',
    agentShield: 'Reads the hidden text and checks it like visible text',
  },
] as const

function FlowStep({ label }: { label: string }) {
  return <li className="rounded-md border border-border bg-background px-3 py-1.5 text-sm font-medium text-foreground">{label}</li>
}

export function KeywordComparison() {
  return (
    <section className="space-y-6" aria-labelledby="keyword-heading">
      <SectionHeader
        id="keyword-heading"
        eyebrow="Why layers"
        title="Why not just keyword filtering?"
        description="A malicious instruction does not always use obvious words. Attackers disguise instructions with encoding, spacing, look-alike characters or invisible Unicode, and OWASP, which ranks prompt injection first in its Top 10 for LLM applications, notes that injected instructions need not be visible to a person at all."
      />

      <div className="grid gap-4 md:grid-cols-2">
        <Card as="article" className="space-y-3">
          <h3 className="font-semibold text-foreground">A keyword filter</h3>
          {/* Vertical on phones (the three steps do not fit one line), a row from `sm`. */}
          <ol className="flex flex-col items-start gap-1.5 sm:flex-row sm:items-center sm:gap-2" aria-label="Keyword filter steps">
            <FlowStep label="Input" />
            <li aria-hidden="true">
              <ArrowRightIcon className="ml-3 size-4 rotate-90 text-muted sm:ml-0 sm:rotate-0" />
            </li>
            <FlowStep label="Keyword match" />
            <li aria-hidden="true">
              <ArrowRightIcon className="ml-3 size-4 rotate-90 text-muted sm:ml-0 sm:rotate-0" />
            </li>
            <FlowStep label="Allow or Block" />
          </ol>
          <p className="text-sm text-muted">One look at the raw text. A disguised instruction has no keyword to match.</p>
        </Card>
        <Card as="article" className="space-y-3 border-primary/40">
          <h3 className="font-semibold text-foreground">AgentShield</h3>
          <p className="text-sm text-foreground">
            Normalises the text, runs several independent detectors, checks again after undoing disguises, can add an AI
            assessment, then scores the combined findings and applies a policy that can also hold an input for human
            review.
          </p>
          <a href="#how-it-works" className="inline-flex min-h-11 items-center gap-1.5 text-sm font-semibold">
            See the full pipeline
            <ArrowRightIcon className="size-4" />
          </a>
        </Card>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-foreground">The same instruction, disguised</h3>
        <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
          <li className="hidden gap-4 bg-background px-4 py-2 text-xs font-semibold tracking-wide text-muted uppercase md:grid md:grid-cols-[1.2fr_1fr_1.3fr]" aria-hidden="true">
            <span>Disguise</span>
            <span>A keyword filter sees</span>
            <span>AgentShield</span>
          </li>
          {disguises.map((row) => (
            <li key={row.technique} className="grid gap-1 px-4 py-3 text-sm md:grid-cols-[1.2fr_1fr_1.3fr] md:gap-4">
              <div>
                <p className="font-semibold text-foreground">{row.technique}</p>
                <p className="font-mono text-xs text-muted">{row.sample}</p>
              </div>
              <p className="text-muted">
                <span className="font-medium text-foreground md:sr-only">A keyword filter sees: </span>
                {row.filter}
              </p>
              <p className="text-foreground">
                <span className="font-medium md:sr-only">AgentShield: </span>
                {row.agentShield}
              </p>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted">
          Not every encoding or disguise is covered; see “What AgentShield does not claim” below.
        </p>
      </div>
    </section>
  )
}
