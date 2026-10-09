import type { ComponentType } from 'react'
import {
  Badge,
  BlockIcon,
  Card,
  CheckCircleIcon,
  ChipIcon,
  InfoIcon,
  WarningIcon,
  type IconProps,
  type Tone,
} from '@/shared/components/ui'
import type { FirewallAnalysis } from '../api/analyzeInput'
import {
  presentDecision,
  presentRiskLevel,
  summariseReasons,
  type AiParticipationPresentation,
  type FindingPresentation,
} from '../model'
import { RiskMeter } from './RiskMeter'

// Class strings are written out in full so Tailwind can find them when scanning the source.
const bannerClass: Record<Tone, string> = {
  neutral: 'border-border bg-background',
  info: 'border-primary/30 bg-primary/10',
  success: 'border-success/30 bg-success/10',
  warning: 'border-warning/30 bg-warning/10',
  danger: 'border-danger/30 bg-danger/10',
  critical: 'border-danger/30 bg-danger/10',
}

const iconClass: Record<Tone, string> = {
  neutral: 'bg-surface text-muted',
  info: 'bg-surface text-primary',
  success: 'bg-surface text-success',
  warning: 'bg-surface text-warning',
  danger: 'bg-surface text-danger',
  critical: 'bg-danger text-surface',
}

const decisionIcon: Record<string, ComponentType<IconProps>> = {
  Allow: CheckCircleIcon,
  Review: WarningIcon,
  Block: BlockIcon,
}

interface DecisionCardProps {
  analysis: FirewallAnalysis
  findings: readonly FindingPresentation[]
  ai: AiParticipationPresentation
  /** The text box has changed since this analysis ran. */
  stale: boolean
}

/** The focal point of a result: what to do with the input, how risky it is, and why. */
export function DecisionCard({ analysis, findings, ai, stale }: DecisionCardProps) {
  const decision = presentDecision(analysis.decision)
  const risk = presentRiskLevel(analysis.risk.level)
  const reasons = summariseReasons(findings)
  // Own entries only: an untrusted decision such as "constructor" must not select an inherited member.
  const DecisionIcon = (Object.hasOwn(decisionIcon, analysis.decision) ? decisionIcon[analysis.decision] : undefined) ?? WarningIcon

  return (
    <Card as="section" padding="none" aria-labelledby="decision-heading" className="overflow-hidden">
      <div className={`flex items-start gap-4 border-b p-4 sm:p-6 ${bannerClass[decision.tone]}`}>
        <span
          className={`flex size-12 shrink-0 items-center justify-center rounded-full shadow-xs ${iconClass[decision.tone]}`}
          aria-hidden="true"
        >
          <DecisionIcon className="size-7" />
        </span>
        <div className="min-w-0 space-y-2">
          <Badge tone={decision.tone} size="md" onTint>
            Decision: {decision.label}
          </Badge>
          <h2 id="decision-heading" className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            {decision.action}
          </h2>
          <p className="max-w-2xl text-foreground">{decision.summary}</p>
        </div>
      </div>

      <div className="space-y-6 p-4 sm:p-6">
        {stale && (
          <p className="flex gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm text-muted">
            <InfoIcon className="mt-0.5 size-4" />
            The text has changed since this analysis. Analyze again to check the current text.
          </p>
        )}

        <dl className="grid gap-4 sm:grid-cols-3">
          <div className="space-y-1">
            <dt className="text-xs font-medium tracking-wide text-muted uppercase">Risk</dt>
            <dd className="flex flex-wrap items-center gap-2">
              <Badge tone={risk.tone}>{risk.label}</Badge>
              <span className="text-sm text-muted tabular-nums">
                <span className="font-semibold text-foreground">{analysis.risk.score}</span> / 100
              </span>
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs font-medium tracking-wide text-muted uppercase">Findings</dt>
            <dd className="text-sm">
              <span className="font-semibold text-foreground tabular-nums">{findings.length}</span>{' '}
              <span className="text-muted">{findings.length === 1 ? 'finding' : 'findings'}</span>
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="text-xs font-medium tracking-wide text-muted uppercase">AI-assisted analysis</dt>
            <dd className="text-sm font-medium text-foreground">{ai.label}</dd>
          </div>
        </dl>

        <RiskMeter score={analysis.risk.score} level={analysis.risk.level} />

        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">Why this decision</h3>
          {reasons.titles.length === 0 ? (
            <p className="text-sm text-muted">No check reported a finding for this input.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {reasons.titles.map((title) => (
                <li key={title} className="flex gap-2">
                  <span className="mt-2 size-1.5 shrink-0 rounded-full bg-foreground" aria-hidden="true" />
                  {title}
                </li>
              ))}
              {reasons.more > 0 && <li className="pl-3.5 text-muted">and {reasons.more} more (see the findings below)</li>}
            </ul>
          )}
        </div>

        <p className="flex gap-2 border-t border-border pt-4 text-sm text-muted">
          <ChipIcon className="mt-0.5 size-4" />
          <span>
            <span className="sr-only">About AI-assisted analysis: </span>
            {ai.description}
          </span>
        </p>
      </div>
    </Card>
  )
}
