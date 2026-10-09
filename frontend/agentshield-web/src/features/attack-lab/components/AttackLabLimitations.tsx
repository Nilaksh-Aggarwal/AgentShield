import { Card, InfoIcon } from '@/shared/components/ui'

const limits = [
  { claim: 'It shows what is built.', detail: 'The Attack Lab demonstrates the controls currently implemented in AgentShield, and nothing more.' },
  {
    claim: 'Detection is keyword rules.',
    detail: 'Known phrasings, mostly English, plus bounded decoding. Paraphrases get through (scenario I-09 shows one).',
  },
  {
    claim: 'No AI is needed here.',
    detail: 'The scenarios are written for the deterministic rules; AI-assisted analysis is off unless the server enables it.',
  },
  {
    claim: 'One tool is enforced.',
    detail: 'Runtime tool enforcement currently covers the reference knowledge.lookup tool, a small built-in dataset. Other tools are authorization-only, not gateway-enforced: for email, browser and the rest AgentShield decides, and stopping the call is the application’s job.',
  },
  {
    claim: 'Human approval is minimal.',
    detail: 'A person can approve or deny a held call, and an approved call runs once. There is no routing, no approver roles and no notifications, and the only call that can run after approval is the read-only lookup held because of its input (T-04): no high-risk tool is behind the gateway.',
  },
  {
    claim: 'Input binding is opt-in.',
    detail: 'A tool call that references its input’s analysis is decided on AgentShield’s own record of it (T-04 does). A call that references none is decided on the action alone, and the caller’s own report can only make it stricter.',
  },
  {
    claim: 'The Development key is one agent.',
    detail: 'It acts as the demo research agent. Elsewhere, a runtime key may choose among the agents bound to it.',
  },
  {
    claim: 'Activity is in memory and not durable.',
    detail: 'Activity, approvals, input records and execution grants live in this API process and are cleared on restart. Activity is a bounded read model, not the audit trail.',
  },
  { claim: 'These are demonstrations.', detail: 'A handful of synthetic scenarios, not a benchmark: no accuracy figures are claimed.' },
] as const

/** What the Attack Lab does not prove, stated next to what it does. */
export function AttackLabLimitations() {
  return (
    <section aria-labelledby="lab-limits-heading">
      <Card className="space-y-4">
        <div className="flex items-center gap-2.5">
          <InfoIcon className="size-5 text-muted" />
          <h2 id="lab-limits-heading" className="text-lg font-semibold tracking-tight text-foreground">
            What these scenarios do not prove
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
