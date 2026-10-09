import { ArrowRightIcon, Badge, ButtonLink, Card } from '@/shared/components/ui'

const stages = [
  { name: 'Agent', text: 'Identified by the API key, never by the request.' },
  { name: 'Action', text: 'A catalogued tool action, such as knowledge.lookup.' },
  { name: 'Capability', text: 'Exactly the one the action requires, held by the agent.' },
  { name: 'Risk', text: 'From what the action does, never from its name or an AI model.' },
  { name: 'Policy', text: 'Allow, Review or Block. Block rules come first.' },
  { name: 'Gateway', text: 'Checks the arguments, issues a single-use grant and checks it.' },
] as const

/**
 * How one tool call travels through AgentShield. A static explanation of the implemented flow, not data: the previews
 * below send real requests through it.
 */
export function AgentSecurityFlow() {
  return (
    <Card as="section" aria-labelledby="flow-heading" className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="flow-heading" className="text-lg font-semibold tracking-tight text-foreground">
          From proposal to execution
        </h2>
        <Badge>How it works</Badge>
      </div>
      <p className="text-sm text-muted">
        The agent only proposes. Each stage below can stop the call, and only the gateway can run a tool: its one reference tool,
        and only on Allow, or once a person approves a call it held.
      </p>
      <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-7">
        {stages.map((stage, index) => (
          <li key={stage.name} className="rounded-lg border border-border bg-background px-3 py-2">
            <span className="flex items-center gap-1.5 text-xs font-semibold text-primary">
              {index + 1}. {stage.name}
              <ArrowRightIcon className="ml-auto hidden size-3.5 text-muted lg:block" />
            </span>
            <span className="block text-xs text-muted">{stage.text}</span>
          </li>
        ))}
        <li className="rounded-lg border border-border bg-background px-3 py-2">
          <span className="block text-xs font-semibold text-primary">7. Execute or stop</span>
          <span className="mt-1 flex flex-wrap gap-1">
            <Badge tone="success">Allow: runs once</Badge>
            <Badge tone="danger">Otherwise: nothing runs</Badge>
          </span>
        </li>
      </ol>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
        <p className="text-sm text-muted">Other tools are decided, not run: stopping them is the application’s job.</p>
        <ButtonLink to="/attack-lab?scenario=T-01" variant="secondary">
          Try it in the Attack Lab
          <ArrowRightIcon />
        </ButtonLink>
      </div>
    </Card>
  )
}
