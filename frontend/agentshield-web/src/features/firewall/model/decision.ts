import type { Tone } from '@/shared/components/ui/tone'
import { ownEntry } from './lookup'

/** How a policy decision is shown: what it means and what the caller should do. */
export interface DecisionPresentation {
  /** Short name of the decision (Allow, Review, Block). */
  label: string
  /** What to do with the input, in plain words. */
  action: string
  /** One or two sentences for readers who do not know the pipeline. */
  summary: string
  tone: Tone
  /** False when the API sent a decision this version of the console does not know. */
  known: boolean
}

type Entry = Omit<DecisionPresentation, 'known'>

// Wording never promises safety: an Allow means no check that ran found a reason to stop the input.
const decisions: Readonly<Record<string, Entry>> = {
  Allow: {
    label: 'Allow',
    action: 'Safe to forward',
    summary:
      'None of the checks that ran found a reason to stop this input. That lowers the risk; it is not a guarantee that the input is harmless.',
    tone: 'success',
  },
  Review: {
    label: 'Review',
    action: 'Hold for human review',
    summary: 'Something in this input needs a person’s judgement before it reaches the agent.',
    tone: 'warning',
  },
  Block: {
    label: 'Block',
    action: 'Do not forward to the agent',
    summary: 'This input shows signs of an attempt to manipulate the agent. It should not be passed on.',
    tone: 'danger',
  },
}

/**
 * Presentation of a policy decision. An unrecognised decision is never shown as safe: it is presented as held for
 * review.
 */
export function presentDecision(decision: string): DecisionPresentation {
  const entry = ownEntry(decisions, decision)
  if (entry) {
    return { ...entry, known: true }
  }

  return {
    label: decision.trim() === '' ? 'Unknown' : decision,
    action: 'Hold for human review',
    summary: 'AgentShield returned a decision this console does not recognise. Treat the input as held for review.',
    tone: 'warning',
    known: false,
  }
}

export interface LevelPresentation {
  label: string
  tone: Tone
}

const riskLevels: Readonly<Record<string, LevelPresentation>> = {
  Low: { label: 'Low risk', tone: 'success' },
  Medium: { label: 'Medium risk', tone: 'warning' },
  High: { label: 'High risk', tone: 'danger' },
  Critical: { label: 'Critical risk', tone: 'critical' },
}

export interface RiskBand {
  level: string
  min: number
  max: number
  tone: Tone
}

/**
 * The score range of each risk level, as the API documents it (`AnalysisResponse`: Low 0–29, Medium 30–69,
 * High 70–89, Critical 90–100). Used only to draw the scale. The console never derives a level or a decision from a
 * score: the level and decision shown are always the ones the API returned.
 */
export const riskBands: readonly RiskBand[] = [
  { level: 'Low', min: 0, max: 29, tone: 'success' },
  { level: 'Medium', min: 30, max: 69, tone: 'warning' },
  { level: 'High', min: 70, max: 89, tone: 'danger' },
  { level: 'Critical', min: 90, max: 100, tone: 'critical' },
]

/** Presentation of the overall risk level. Unknown levels are shown by name, in a neutral tone. */
export function presentRiskLevel(level: string): LevelPresentation {
  return ownEntry(riskLevels, level) ?? { label: level.trim() === '' ? 'Unknown risk' : `${level} risk`, tone: 'neutral' }
}

const severities: Readonly<Record<string, LevelPresentation>> = {
  Low: { label: 'Low', tone: 'neutral' },
  Medium: { label: 'Medium', tone: 'warning' },
  High: { label: 'High', tone: 'danger' },
  Critical: { label: 'Critical', tone: 'critical' },
}

/** Presentation of a finding's severity. Unknown severities are shown by name, in a neutral tone. */
export function presentSeverity(severity: string): LevelPresentation {
  return ownEntry(severities, severity) ?? { label: severity.trim() === '' ? 'Unknown' : severity, tone: 'neutral' }
}
