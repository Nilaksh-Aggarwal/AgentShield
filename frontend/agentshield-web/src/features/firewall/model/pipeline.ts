import type { AiParticipationPresentation } from './ai'
import type { DecisionPresentation, LevelPresentation } from './decision'
import type { FindingPresentation } from './findings'

export type PipelineStageId =
  | 'input'
  | 'normalize'
  | 'rules'
  | 'obfuscation'
  | 'ai'
  | 'aggregation'
  | 'risk'
  | 'policy'
  | 'decision'

export interface PipelineStage {
  id: PipelineStageId
  name: string
  /** One plain-English line; says what the stage does, never how it detects. */
  description: string
}

/**
 * The stages of `POST /api/v1/firewall/analyze`, in the order the backend runs them (docs/security/firewall-pipeline.md).
 * The obfuscation check runs with the other detectors; it is shown separately because it is a distinct kind of check.
 */
export const pipelineStages: readonly PipelineStage[] = [
  { id: 'input', name: 'Input', description: 'Receives the untrusted text exactly as sent. It is never stored.' },
  {
    id: 'normalize',
    name: 'Normalize',
    description: 'Removes invisible characters and converts equivalent Unicode forms into one consistent form.',
  },
  {
    id: 'rules',
    name: 'Rule detection',
    description: 'Looks for known instruction-override, role and secret-extraction patterns.',
  },
  {
    id: 'obfuscation',
    name: 'Obfuscation check',
    description: 'Looks for attacks hidden by encoding, character disguises or invisible characters.',
  },
  {
    id: 'ai',
    name: 'AI analysis',
    description: 'Optional additional signal, when enabled and within capacity. It can add findings, never decide.',
  },
  {
    id: 'aggregation',
    name: 'Finding aggregation',
    description: 'Merges duplicate findings, keeping their evidence, so one issue is not counted twice.',
  },
  { id: 'risk', name: 'Risk engine', description: 'Calculates a risk level and a score out of 100 from the findings.' },
  { id: 'policy', name: 'Policy', description: 'Applies the security policy: Allow, Review or Block.' },
  {
    id: 'decision',
    name: 'Decision',
    description: 'Returned to the caller and recorded as a security event, without the input text.',
  },
]

/**
 * - `clear`: the stage ran and reported nothing;
 * - `flagged`: the stage contributed findings;
 * - `held`: the stage could not complete, and the input is held for review;
 * - `unknown`: the response does not say what the stage did (AI analysis may be off or skipped);
 * - `done`: the stage ran and produced its result.
 */
export type StageStatus = 'clear' | 'flagged' | 'held' | 'unknown' | 'done'

export interface StageOutcome {
  status: StageStatus
  summary: string
}

export interface PipelineInput {
  findings: readonly FindingPresentation[]
  decision: DecisionPresentation
  risk: LevelPresentation
  score: number
  ai: AiParticipationPresentation
  /** Characters submitted, when known. */
  inputLength?: number
}

/**
 * What a completed response proves about each stage. The API answers only after every stage has run, so a result
 * marks all stages finished; the per-stage summary is read from the findings, never estimated.
 */
export function pipelineOutcomes({ findings, decision, risk, score, ai, inputLength }: PipelineInput): Record<PipelineStageId, StageOutcome> {
  const obfuscation = findings.filter((finding) => finding.category === 'Obfuscation' && finding.source !== 'ai').length
  const rules = findings.filter((finding) => finding.source === 'rules' && finding.category !== 'Obfuscation').length
  const aiAdded = findings.filter((finding) => finding.source === 'ai').length

  return {
    input: {
      status: 'done',
      summary: inputLength === undefined ? 'Received' : `${inputLength.toLocaleString()} characters received`,
    },
    normalize: { status: 'done', summary: 'Completed' },
    rules: counted(rules),
    obfuscation: counted(obfuscation),
    ai:
      ai.state === 'contributed'
        ? { status: 'flagged', summary: `Added ${plural(aiAdded, 'finding')}` }
        : ai.state === 'incomplete'
          ? { status: 'held', summary: 'Could not complete: held for review' }
          : { status: 'unknown', summary: 'No AI findings reported' },
    aggregation: { status: 'done', summary: `${plural(findings.length, 'finding')} in total` },
    risk: { status: 'done', summary: `${risk.label}, ${score}/100` },
    policy: { status: 'done', summary: decision.label },
    decision: { status: 'done', summary: decision.action },
  }
}

function counted(count: number): StageOutcome {
  return count === 0 ? { status: 'clear', summary: 'No findings' } : { status: 'flagged', summary: plural(count, 'finding') }
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}
