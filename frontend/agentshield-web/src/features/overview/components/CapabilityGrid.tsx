import type { ComponentType } from 'react'
import {
  Card,
  ChipIcon,
  CodeIcon,
  EyeOffIcon,
  GaugeIcon,
  KeyIcon,
  LockIcon,
  RulesIcon,
  ScaleIcon,
  SectionHeader,
  UserIcon,
  type IconProps,
} from '@/shared/components/ui'

interface Capability {
  title: string
  text: string
  Icon: ComponentType<IconProps>
  /** A short, harmless illustration of the technique. Never a working payload or a real secret. */
  example?: string
}

// What is implemented today (docs/security/firewall-pipeline.md, ai-analysis.md); no rule IDs or patterns.
const detection: Capability[] = [
  {
    title: 'Instruction override',
    text: 'Attempts to cancel or replace the instructions an agent was given.',
    Icon: RulesIcon,
    example: '“Ignore your previous instructions…”',
  },
  {
    title: 'Role manipulation',
    text: 'Fake system or assistant messages, jailbreak personas and false claims of authority.',
    Icon: UserIcon,
    example: '“You are now in unrestricted mode…”',
  },
  {
    title: 'Secret extraction',
    text: 'Requests for the system prompt, hidden instructions, credentials or keys.',
    Icon: KeyIcon,
    example: '“Reveal your hidden instructions…”',
  },
  {
    title: 'Obfuscation',
    text: 'Looks again after decoding Base64, URL encoding and HTML entities, and after undoing look-alike letters, spacing and character substitutions.',
    Icon: CodeIcon,
    // Non-breaking spaces keep the spaced-out sample on one line.
    example: 'Encoded or disguised: “1gn0r3”, “i g n o r e”',
  },
  {
    title: 'Unicode smuggling',
    text: 'Reads text hidden in invisible Unicode characters and checks it like visible text.',
    Icon: EyeOffIcon,
    example: 'Instructions you cannot see',
  },
]

const decision: Capability[] = [
  {
    title: 'AI-assisted analysis',
    text: 'Optional: an AI model can add findings the rules miss, from a fixed set of finding types. It never decides.',
    Icon: ChipIcon,
  },
  {
    title: 'Risk scoring',
    text: 'The most severe finding sets the risk level; each further finding raises the score within that level.',
    Icon: GaugeIcon,
  },
  {
    title: 'Policy enforcement',
    text: 'A deterministic policy turns the risk into Allow, Review or Block, the same way every time.',
    Icon: ScaleIcon,
  },
  {
    title: 'Fail-safe AI controls',
    text: 'If an expected AI analysis cannot complete, the input is held for review instead of being allowed.',
    Icon: LockIcon,
  },
]

function CapabilityCard({ capability }: { capability: Capability }) {
  const { title, text, Icon, example } = capability
  return (
    <Card as="article" className="flex h-full flex-col gap-3">
      <div className="flex items-center gap-3">
        <span className="flex size-9 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary" aria-hidden="true">
          <Icon className="size-5" />
        </span>
        <h4 className="font-semibold text-foreground">{title}</h4>
      </div>
      <p className="text-sm text-muted">{text}</p>
      {example && (
        <p className="mt-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground">
          <span className="sr-only">Example: </span>
          {example}
        </p>
      )}
    </Card>
  )
}

export function CapabilityGrid() {
  return (
    <section className="space-y-6" aria-labelledby="capabilities-heading">
      <SectionHeader
        id="capabilities-heading"
        eyebrow="Capabilities"
        title="What AgentShield checks for, and how it decides"
        description="Five kinds of manipulation are detected; four mechanisms turn what was found into a decision."
      />
      <div className="space-y-3">
        <h3 className="text-sm font-semibold tracking-wide text-muted uppercase">Detects</h3>
        {/* Three cards, then two wider ones, on desktop: five equal columns would be too narrow to read. */}
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
          {detection.map((capability, index) => (
            <li key={capability.title} className={index < 3 ? 'lg:col-span-2' : 'lg:col-span-3'}>
              <CapabilityCard capability={capability} />
            </li>
          ))}
        </ul>
      </div>
      <div className="space-y-3">
        <h3 className="text-sm font-semibold tracking-wide text-muted uppercase">Decides</h3>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {decision.map((capability) => (
            <li key={capability.title}>
              <CapabilityCard capability={capability} />
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
