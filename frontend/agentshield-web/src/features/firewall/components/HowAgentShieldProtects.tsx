import { Card, ScaleIcon, SectionHeader } from '@/shared/components/ui'

const steps = [
  { title: 'Rules catch known attacks', text: 'Deterministic rules look for instruction overrides, fake system messages and requests for secrets.' },
  { title: 'Disguises are undone', text: 'Obfuscation checks look again after decoding and undoing disguises, including invisible characters.' },
  { title: 'AI adds a signal', text: 'When enabled and within its capacity, AI-assisted analysis can add findings the rules missed.' },
  { title: 'Findings are combined', text: 'Duplicate findings are merged, so one issue is not counted twice.' },
  { title: 'Risk is calculated', text: 'The risk engine turns the findings into a risk level and a score out of 100.' },
  { title: 'The policy decides', text: 'A deterministic policy turns the risk into Allow, Review or Block.' },
] as const

/** The defence-in-depth model in six plain steps, and the rule that matters most: the AI never decides. */
export function HowAgentShieldProtects() {
  return (
    <section className="space-y-4" aria-labelledby="protects-heading">
      <SectionHeader
        id="protects-heading"
        title="How AgentShield protects your input"
        description="Several independent layers look at every input; the final decision always comes from the deterministic policy."
      />
      <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {steps.map((step, index) => (
          <li key={step.title}>
            <Card className="flex h-full gap-3">
              <span
                className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-sm font-semibold text-primary"
                aria-hidden="true"
              >
                {index + 1}
              </span>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-foreground">{step.title}</h3>
                <p className="text-sm text-muted">{step.text}</p>
              </div>
            </Card>
          </li>
        ))}
      </ol>
      <p className="flex gap-3 rounded-lg border border-primary/30 bg-primary/10 p-4 text-sm text-foreground">
        <ScaleIcon className="mt-0.5 size-5 text-primary" />
        <span>
          <strong className="font-semibold">AI never overrides the policy.</strong> AI-assisted analysis can add findings,
          but it cannot remove a finding, lower the risk or make the decision. If an expected AI analysis fails, the input
          is held for review rather than allowed.
        </span>
      </p>
    </section>
  )
}
