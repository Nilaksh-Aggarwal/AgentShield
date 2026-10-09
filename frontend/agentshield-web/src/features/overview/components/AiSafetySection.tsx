import type { ReactNode } from 'react'
import { presentDecision } from '@/features/firewall'
import {
  ArrowDownIcon,
  Badge,
  Card,
  ChipIcon,
  GaugeIcon,
  LayersIcon,
  RulesIcon,
  ScaleIcon,
  SectionHeader,
  type Tone,
} from '@/shared/components/ui'

// Every row is the implemented behaviour (ADR 0016, docs/security/ai-analysis.md, failure table). "Held for review"
// applies to inputs the rules would allow or review; an input the rules block stays blocked.
const situations: { situation: string; outcome: string; label: string; tone: Tone }[] = [
  { situation: 'AI analysis is not enabled on the server', outcome: 'The rules and the policy decide alone.', label: 'Rules decide', tone: 'neutral' },
  {
    situation: 'The rules already block the input',
    outcome: 'The AI is not asked (the default setting); the input stays blocked either way.',
    label: 'Skipped',
    tone: 'neutral',
  },
  { situation: 'The AI analysis completes', outcome: 'Its findings join the rule findings; the policy decides.', label: 'Adds findings', tone: 'info' },
  { situation: 'The AI times out, is unavailable or rate-limited', outcome: 'Held for review, never silently allowed.', label: 'Review', tone: 'warning' },
  { situation: 'The circuit breaker is open after repeated failures', outcome: 'No call is made; held for review.', label: 'Review', tone: 'warning' },
  { situation: 'AgentShield’s own AI budget is used up', outcome: 'No call is made; held for review.', label: 'Review', tone: 'warning' },
  { situation: 'The AI’s answer is malformed, invalid or a refusal', outcome: 'The answer is discarded; held for review.', label: 'Review', tone: 'warning' },
]

function FlowBox({ icon, title, text, dashed = false }: { icon: ReactNode; title: string; text: string; dashed?: boolean }) {
  return (
    <div className={`flex gap-3 rounded-lg border bg-surface p-3 ${dashed ? 'border-dashed border-primary/60' : 'border-border'}`}>
      <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-background text-muted" aria-hidden="true">
        {icon}
      </span>
      <div>
        <p className="text-sm font-semibold text-foreground">{title}</p>
        <p className="text-xs text-muted">{text}</p>
      </div>
    </div>
  )
}

function Down() {
  return (
    <div className="flex justify-center py-1 text-muted" aria-hidden="true">
      <ArrowDownIcon className="size-4" />
    </div>
  )
}

export function AiSafetySection() {
  const decisions = ['Allow', 'Review', 'Block'].map(presentDecision)

  return (
    <section className="space-y-6" aria-labelledby="ai-safety-heading">
      <SectionHeader
        id="ai-safety-heading"
        eyebrow="AI safety"
        title="The AI is a signal, not the authority"
        description="AI provides an additional signal. It does not get to decide whether an input is allowed: it can add findings, but it cannot remove or lower a rule finding, and it has no say in the policy."
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Card as="article" aria-labelledby="decision-flow-heading">
          <h3 id="decision-flow-heading" className="mb-4 font-semibold text-foreground">
            Where the decision comes from
          </h3>
          <ol className="space-y-0" aria-label="From checks to decision">
            <li className="grid gap-1 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] sm:items-center sm:gap-2">
              <FlowBox icon={<RulesIcon className="size-4" />} title="Deterministic security" text="Rules and obfuscation checks" />
              <span className="text-center text-lg font-semibold text-muted" aria-hidden="true">
                +
              </span>
              <FlowBox icon={<ChipIcon className="size-4" />} title="AI-assisted analysis" text="Optional; adds findings only" dashed />
            </li>
            <li>
              <Down />
              <FlowBox icon={<LayersIcon className="size-4" />} title="Findings" text="Merged, evidence kept" />
            </li>
            <li>
              <Down />
              <FlowBox icon={<GaugeIcon className="size-4" />} title="Risk engine" text="Risk level and score from the findings" />
            </li>
            <li>
              <Down />
              <FlowBox icon={<ScaleIcon className="size-4" />} title="Policy engine" text="The only place a decision is made" />
            </li>
            <li>
              <Down />
              <div className="grid gap-2 sm:grid-cols-3">
                {decisions.map((decision) => (
                  <div key={decision.label} className="rounded-lg border border-border bg-background p-3 text-center">
                    <Badge tone={decision.tone}>{decision.label}</Badge>
                    <p className="mt-1.5 text-xs text-foreground">{decision.action}</p>
                  </div>
                ))}
              </div>
            </li>
          </ol>
        </Card>

        <Card as="article" padding="none" aria-labelledby="ai-failures-heading">
          <div className="border-b border-border px-4 py-3 sm:px-6">
            <h3 id="ai-failures-heading" className="font-semibold text-foreground">
              What happens when the AI can’t help
            </h3>
            <p className="text-sm text-muted">Failures never turn into a silent Allow.</p>
          </div>
          <ul className="divide-y divide-border">
            {situations.map((row) => (
              <li key={row.situation} className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 px-4 py-3 sm:px-6">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground">{row.situation}</p>
                  <p className="text-sm text-muted">{row.outcome}</p>
                </div>
                <Badge tone={row.tone}>{row.label}</Badge>
              </li>
            ))}
          </ul>
          <p className="border-t border-border px-4 py-3 text-xs text-muted sm:px-6">
            “Held for review” applies to inputs the rules would allow or send to review. An input the rules block stays
            blocked whatever happens to the AI.
          </p>
        </Card>
      </div>
    </section>
  )
}
