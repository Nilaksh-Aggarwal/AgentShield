import type { Tone } from '@/shared/components/ui/tone'
import type { FindingPresentation } from './findings'

/**
 * What a response proves about AI-assisted analysis. The API deliberately does not return the AI status (it would tell
 * an attacker whether they stalled, confused or exhausted the analyser), so only three states can be told apart:
 * - `contributed`: an `*.AiDetected` finding is present, so the AI analysis completed and added findings;
 * - `incomplete`: the safeguard finding is present, so an expected AI analysis did not complete (timeout, outage, open
 *   circuit, exhausted capacity, invalid answer: deliberately indistinguishable) and the input is held for review;
 * - `not-reported`: neither, so AI analysis is off or found nothing, or, for a Block only, was skipped because the rules
 *   had already blocked the input (a failure to complete is never silent: it adds the safeguard finding).
 */
export type AiParticipation = 'contributed' | 'incomplete' | 'not-reported'

export interface AiParticipationPresentation {
  state: AiParticipation
  /** Short status, e.g. for a fact row or the pipeline. */
  label: string
  /** One or two sentences on what it means for this decision. */
  description: string
  tone: Tone
}

const AiIncompleteCode = 'InconclusiveAnalysis.AiAnalysisIncomplete'

/**
 * @param findings The analysis's findings.
 * @param decision The API's decision: only a Block can have skipped the AI analysis.
 */
export function presentAiParticipation(findings: readonly FindingPresentation[], decision: string): AiParticipationPresentation {
  if (findings.some((finding) => finding.code === AiIncompleteCode)) {
    return {
      state: 'incomplete',
      label: 'AI analysis could not be completed',
      description:
        'The input is held for review instead of being allowed. Whether the AI analysis timed out, was unavailable or reached its capacity limit is recorded in the audit log but not shown here, so the result cannot be used to probe the analyser.',
      tone: 'warning',
    }
  }

  const aiFindings = findings.filter((finding) => finding.source === 'ai').length
  if (aiFindings > 0) {
    return {
      state: 'contributed',
      label: 'AI-assisted analysis completed',
      description: `It added ${aiFindings === 1 ? 'one finding' : `${aiFindings} findings`}, which were combined with the rule findings. The security policy, not the AI, made the decision.`,
      tone: 'info',
    }
  }

  return {
    state: 'not-reported',
    label: 'No AI findings reported',
    description:
      decision === 'Block'
        ? 'AI-assisted analysis is off on this server, found nothing, or was skipped because the rules had already blocked the input. The response does not say which; the rules and the policy decided either way.'
        : 'AI-assisted analysis is off on this server or found nothing. The response does not say which; the rules and the policy decided either way.',
    tone: 'neutral',
  }
}
