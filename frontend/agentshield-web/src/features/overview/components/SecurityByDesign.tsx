import type { ComponentType } from 'react'
import {
  Card,
  CircuitOffIcon,
  ClipboardCheckIcon,
  GaugeIcon,
  LockIcon,
  ScaleIcon,
  SectionHeader,
  ShieldIcon,
  UserIcon,
  WarningIcon,
  type IconProps,
} from '@/shared/components/ui'

// Only protections that are implemented and tested (docs/security/principles.md, ADRs 0011–0016).
const protections: { title: string; text: string; Icon: ComponentType<IconProps> }[] = [
  {
    title: 'Fail-safe AI',
    text: 'When an expected AI analysis cannot complete, the input is held for review, never silently treated as safe.',
    Icon: ShieldIcon,
  },
  {
    title: 'Bounded AI usage',
    text: 'AgentShield’s own budgets limit AI requests per minute and per day, concurrent calls and input tokens, per client and in total, before any provider call.',
    Icon: GaugeIcon,
  },
  {
    title: 'Circuit breaker',
    text: 'After repeated provider failures, calls stop for a short time; a single test call checks whether the provider has recovered.',
    Icon: CircuitOffIcon,
  },
  {
    title: 'Strict AI output validation',
    text: 'AI answers must match a fixed structure and a fixed set of finding types. Anything else is rejected as a whole.',
    Icon: ClipboardCheckIcon,
  },
  {
    title: 'No decision field for the model',
    text: 'The AI’s answer has no place for Allow, Review or Block, only findings. Model-written text is never shown.',
    Icon: ScaleIcon,
  },
  {
    title: 'Privacy-conscious logging',
    text: 'Security events record decisions and finding codes, never the input, prompts, provider responses or secrets. Secrets are masked before text reaches an AI provider.',
    Icon: LockIcon,
  },
  {
    title: 'Human review',
    text: 'Review is a decision in its own right, for uncertain inputs and for analyses that could not complete.',
    Icon: UserIcon,
  },
  {
    title: 'Bounded detection',
    text: 'Detection runs in linear time within fixed inspection limits. Content too large to inspect fully is held for review, not skipped.',
    Icon: WarningIcon,
  },
]

export function SecurityByDesign() {
  return (
    <section className="space-y-6" aria-labelledby="by-design-heading">
      <SectionHeader
        id="by-design-heading"
        eyebrow="Security by design"
        title="Protections built in"
        description="Safeguards around the analysis itself, so that failures, load or a misbehaving model cannot weaken the decision."
      />
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {protections.map(({ title, text, Icon }) => (
          <li key={title}>
            <Card as="article" className="h-full space-y-2">
              <div className="flex items-center gap-2.5">
                <Icon className="size-5 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">{title}</h3>
              </div>
              <p className="text-sm text-muted">{text}</p>
            </Card>
          </li>
        ))}
      </ul>
    </section>
  )
}
