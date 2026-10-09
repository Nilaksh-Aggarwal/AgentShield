import type { FirewallAnalysisResult } from '../api/analyzeInput'
import type { AiParticipationPresentation, FindingPresentation } from '../model'
import { DecisionCard } from './DecisionCard'
import { FindingsSection } from './FindingsSection'
import { TechnicalDetails } from './TechnicalDetails'

interface AnalysisResultProps {
  result: FirewallAnalysisResult
  findings: readonly FindingPresentation[]
  ai: AiParticipationPresentation
  stale: boolean
}

/** A completed analysis: the decision first, then the findings behind it, then technical details (collapsed). */
export function AnalysisResult({ result, findings, ai, stale }: AnalysisResultProps) {
  return (
    <div className="space-y-6">
      <DecisionCard analysis={result.analysis} findings={findings} ai={ai} stale={stale} />
      <FindingsSection findings={findings} />
      <TechnicalDetails result={result} findings={findings} ai={ai} />
    </div>
  )
}
