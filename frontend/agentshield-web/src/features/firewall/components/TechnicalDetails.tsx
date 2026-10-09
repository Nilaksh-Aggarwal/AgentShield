import type { ReactNode } from 'react'
import { ChevronDownIcon } from '@/shared/components/ui'
import type { FirewallAnalysisResult } from '../api/analyzeInput'
import type { AiParticipationPresentation, FindingPresentation } from '../model'

interface TechnicalDetailsProps {
  result: FirewallAnalysisResult
  findings: readonly FindingPresentation[]
  ai: AiParticipationPresentation
}

/**
 * Identifiers and raw values for technical users, collapsed by default. Everything here is part of the public API
 * response; nothing is added from elsewhere.
 */
export function TechnicalDetails({ result, findings, ai }: TechnicalDetailsProps) {
  const { analysis } = result
  const receivedAt = new Date(result.timestamp)

  return (
    <details className="group rounded-lg border border-border bg-surface">
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 rounded-lg px-4 py-2 text-sm font-semibold text-foreground sm:px-6 [&::-webkit-details-marker]:hidden">
        Technical details
        <ChevronDownIcon className="size-4 text-muted motion-safe:transition-transform group-open:rotate-180" />
      </summary>
      <dl className="grid gap-x-6 gap-y-4 border-t border-border px-4 py-4 text-sm sm:grid-cols-[auto_minmax(0,1fr)] sm:gap-y-3 sm:px-6">
        <Detail term="Decision (API value)">
          <code className="font-mono">{analysis.decision}</code>
        </Detail>
        <Detail term="Policy reason">{analysis.reason}</Detail>
        <Detail term="Risk">
          <code className="font-mono">{analysis.risk.level}</code>, score{' '}
          <span className="tabular-nums">{analysis.risk.score}</span> of 100
        </Detail>
        <Detail term="Finding codes">
          {findings.length === 0 ? (
            'None'
          ) : (
            <ul className="space-y-0.5">
              {findings.map((finding) => (
                <li key={`${finding.category}:${finding.code}`}>
                  <code className="font-mono text-xs break-all">{finding.code}</code>{' '}
                  <span className="text-muted">({finding.sourceLabel})</span>
                </li>
              ))}
            </ul>
          )}
        </Detail>
        <Detail term="AI-assisted analysis">{ai.label}</Detail>
        <Detail term="Security event ID">
          <code className="font-mono break-all">{analysis.securityEventId}</code>
        </Detail>
        <Detail term="Correlation ID">
          <code className="font-mono break-all">{result.correlationId}</code>
        </Detail>
        <Detail term="Analysis time">
          <span className="tabular-nums">{analysis.durationMs.toFixed(2)} ms</span> on the server
        </Detail>
        <Detail term="Responded at">
          {Number.isNaN(receivedAt.getTime()) ? result.timestamp : receivedAt.toLocaleString()}
        </Detail>
      </dl>
    </details>
  )
}

// Each term and its value are grouped (valid inside <dl>), so stacked on phones the pairs stay visibly together; from
// `sm` the group dissolves (`contents`) into the two-column grid.
function Detail({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5 sm:contents">
      <dt className="text-muted">{term}</dt>
      <dd className="min-w-0 text-foreground">{children}</dd>
    </div>
  )
}
