import { Card, InfoIcon } from '@/shared/components/ui'

const limits = [
  { claim: 'Allow is not a guarantee.', detail: 'It means no check found a reason to stop the input.' },
  { claim: 'The AI is not an authority.', detail: 'Its findings are one signal; the deterministic policy decides.' },
  {
    claim: 'Coverage is not universal.',
    detail: 'Rules match known phrasings, mostly in English; paraphrases, other languages and other encodings can get through.',
  },
  {
    claim: 'The evaluation is limited.',
    detail: 'AgentShield has been tested on a small synthetic dataset only. No accuracy figures are claimed.',
  },
  { claim: 'AI behaviour can vary.', detail: 'The same input can get a different AI assessment on another run.' },
  { claim: 'Review exists for uncertainty.', detail: 'When the checks cannot be sure, or cannot finish, a person decides.' },
  {
    claim: 'Only one tool is enforced.',
    detail: 'AgentShield’s tool gateway runs its built-in reference tool only on Allow, or after a person approves a held call; for every other tool it decides, and stopping the call is up to the application running the agent.',
  },
] as const

/** Honest limits, stated briefly: a security product should not imply perfect protection. */
export function Limitations() {
  return (
    <section aria-labelledby="limits-heading">
      <Card className="space-y-4">
        <div className="flex items-center gap-2.5">
          <InfoIcon className="size-5 text-muted" />
          <h2 id="limits-heading" className="text-lg font-semibold tracking-tight text-foreground">
            What AgentShield does not claim
          </h2>
        </div>
        <ul className="grid gap-x-8 gap-y-3 text-sm md:grid-cols-2">
          {limits.map(({ claim, detail }) => (
            <li key={claim}>
              <span className="font-semibold text-foreground">{claim}</span> <span className="text-muted">{detail}</span>
            </li>
          ))}
        </ul>
      </Card>
    </section>
  )
}
