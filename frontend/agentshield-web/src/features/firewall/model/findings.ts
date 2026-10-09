import type { ThreatFinding } from '../api/analyzeInput'
import { presentSeverity, type LevelPresentation } from './decision'
import { ownEntry } from './lookup'

/**
 * Where a finding came from, as far as the API lets a client tell:
 * - `rules`: AgentShield's deterministic detection rules;
 * - `ai`: the optional AI-assisted analysis (codes ending in `.AiDetected`);
 * - `system`: a safeguard, not an attack (content that could not be fully inspected, an AI analysis that could not
 *   complete); it holds the input for review instead of letting it through unchecked.
 */
export type FindingSource = 'rules' | 'ai' | 'system'

export const findingSourceLabels: Readonly<Record<FindingSource, string>> = {
  rules: 'Rules',
  ai: 'AI-assisted',
  system: 'System',
}

export interface ConfidencePresentation {
  /** What the number is, e.g. "Rule confidence (heuristic)". Never presented as a probability. */
  label: string
  /** Coarse reading of the number. */
  level: 'High' | 'Moderate' | 'Low'
}

export interface FindingPresentation {
  /** Stable finding code from the API (public contract, safe to show). */
  code: string
  /** Category name as the API sent it (empty when missing). */
  category: string
  title: string
  description: string
  categoryLabel: string
  severity: LevelPresentation
  source: FindingSource
  sourceLabel: string
  /** `null` where a confidence says nothing (system safeguards) or the value is unusable. */
  confidence: ConfidencePresentation | null
  recommendedAction: string
  /** False when the code is not in this console's catalogue (a newer API); the presentation is then generic. */
  known: boolean
}

interface CatalogueEntry {
  title: string
  description: string
  source: FindingSource
  /** Overrides the category's recommended action. */
  action?: string
}

/**
 * Plain-language presentation of every finding code the API currently returns. Describes what the input tries to do,
 * never how it was detected (no patterns, rule IDs, decoded content or model output).
 */
const catalogue: Readonly<Record<string, CatalogueEntry>> = {
  'InstructionOverride.IgnorePrevious': {
    title: 'Instruction override detected',
    description: 'The input tells the AI to ignore or override the instructions it was given.',
    source: 'rules',
  },
  'InstructionOverride.DiscardContext': {
    title: 'Attempt to erase earlier instructions',
    description: 'The input tells the AI to disregard everything it was told before this message.',
    source: 'rules',
  },
  'InstructionOverride.NewInstructions': {
    title: 'Replacement instructions supplied',
    description: 'The input presents new instructions for the AI to follow instead of its own.',
    source: 'rules',
  },
  'RoleManipulation.ForgedRoleDelimiter': {
    title: 'Forged system or assistant message',
    description: 'The input contains chat-format control markers that impersonate a system or assistant message.',
    source: 'rules',
  },
  'RoleManipulation.UnrestrictedPersona': {
    title: 'Jailbreak persona requested',
    description: 'The input asks the AI to take on a persona that ignores its safety rules.',
    source: 'rules',
  },
  'RoleManipulation.AuthorityClaim': {
    title: 'False claim of authority',
    description: 'The input presents itself as coming from the system, a developer or an administrator.',
    source: 'rules',
  },
  'SecretExtraction.SystemPromptDisclosure': {
    title: 'Attempt to extract hidden instructions',
    description: 'The input asks the AI to reveal its system prompt or other hidden instructions.',
    source: 'rules',
  },
  'SecretExtraction.CredentialDisclosure': {
    title: 'Attempt to extract credentials',
    description: 'The input asks the AI to reveal passwords, API keys or other secrets.',
    source: 'rules',
  },
  'Obfuscation.EncodedThreat': {
    title: 'Hidden instruction found after decoding',
    description: 'Part of the input was encoded to hide a manipulation attempt, which was found once it was decoded.',
    source: 'rules',
  },
  // One code covers look-alike letters, character substitutions, spaced-out letters and invisible characters, so the
  // title names the disguise in general rather than one technique.
  'Obfuscation.MaskedThreat': {
    title: 'Disguised instruction detected',
    description:
      'Part of the input was disguised, for example with look-alike letters, character substitutions or invisible characters, to hide a manipulation attempt.',
    source: 'rules',
  },
  'Obfuscation.UninspectableContent': {
    title: 'Content too complex to inspect fully',
    description:
      'Encoded or disguised content went beyond the inspection limits, so it could not be fully checked. It is held for review rather than allowed.',
    source: 'system',
    action: 'Have a person review the input, or resend it as plain text.',
  },
  'InstructionOverride.AiDetected': {
    title: 'Instruction override (AI-assisted)',
    description: 'AI-assisted analysis indicates an attempt to override or replace the AI’s instructions.',
    source: 'ai',
  },
  'RoleManipulation.AiDetected': {
    title: 'Role manipulation (AI-assisted)',
    description: 'AI-assisted analysis indicates an attempt to change the AI’s role or to impersonate a trusted speaker.',
    source: 'ai',
  },
  'SecretExtraction.AiDetected': {
    title: 'Secret extraction (AI-assisted)',
    description: 'AI-assisted analysis indicates an attempt to extract instructions, credentials or other protected data.',
    source: 'ai',
  },
  'Obfuscation.AiDetected': {
    title: 'Disguised manipulation (AI-assisted)',
    description: 'AI-assisted analysis indicates a manipulation attempt hidden by encoding or disguise.',
    source: 'ai',
  },
  // The reason the AI analysis did not complete is deliberately not part of the API (it would tell an attacker whether
  // they stalled or confused the analyser), so the description does not guess at one.
  'InconclusiveAnalysis.AiAnalysisIncomplete': {
    title: 'AI analysis could not be completed',
    description:
      'The optional AI analysis could not assess this input, so it is held for review instead of being allowed.',
    source: 'system',
  },
}

interface CategoryEntry {
  label: string
  action: string
}

const categories: Readonly<Record<string, CategoryEntry>> = {
  InstructionOverride: {
    label: 'Instruction override',
    action: 'Do not pass this text to the agent as instructions; the agent’s own instructions must stay in control.',
  },
  RoleManipulation: {
    label: 'Role manipulation',
    action: 'Treat role and authority claims inside user content as untrusted text, never as system messages.',
  },
  SecretExtraction: {
    label: 'Secret extraction',
    action: 'Make sure the agent cannot disclose its instructions, keys or other secrets in reply to this input.',
  },
  Obfuscation: {
    label: 'Obfuscation',
    action: 'Do not decode or act on hidden content on the agent’s behalf.',
  },
  InconclusiveAnalysis: {
    label: 'Inconclusive analysis',
    action: 'Have a person review the input before it reaches the agent.',
  },
}

const genericAction = 'Review the input before it reaches the agent.'
const genericDescription = 'AgentShield reported a finding that this version of the console does not describe yet.'

/** Plain-language presentation of one finding. Unknown codes and categories get a safe, generic presentation. */
export function presentFinding(finding: ThreatFinding): FindingPresentation {
  const code = asText(finding.code)
  const category = asText(finding.category)
  const categoryEntry = ownEntry(categories, category)
  const categoryLabel = categoryEntry?.label ?? humanize(category)
  const entry = ownEntry(catalogue, code)
  const source = entry?.source ?? inferSource(code, category)

  return {
    code,
    category,
    title: entry?.title ?? fallbackTitle(source, categoryEntry ? categoryLabel : undefined),
    description: entry?.description ?? fallbackDescription(finding.description),
    categoryLabel,
    severity: presentSeverity(asText(finding.severity)),
    source,
    sourceLabel: findingSourceLabels[source],
    confidence: presentConfidence(source, finding.confidence),
    recommendedAction: entry?.action ?? categoryEntry?.action ?? genericAction,
    known: entry !== undefined,
  }
}

/**
 * The findings behind a decision, for a one-line "why": the titles of the first `limit` findings (the API sends them
 * most severe first) and how many more there are.
 */
export function summariseReasons(findings: readonly FindingPresentation[], limit = 3): { titles: string[]; more: number } {
  const titles = [...new Set(findings.map((finding) => finding.title))]
  return { titles: titles.slice(0, limit), more: Math.max(0, titles.length - limit) }
}

/**
 * Confidence is an estimate written by a rule's author (or reported by the AI model), not a measured probability, so it
 * is shown as a coarse level with a label that says so, never as a percentage.
 */
function presentConfidence(source: FindingSource, value: number): ConfidencePresentation | null {
  if (source === 'system' || !Number.isFinite(value) || value < 0 || value > 1) {
    return null
  }

  return {
    label: source === 'ai' ? 'AI-reported confidence (uncalibrated)' : 'Rule confidence (heuristic)',
    level: value >= 0.8 ? 'High' : value >= 0.6 ? 'Moderate' : 'Low',
  }
}

// For codes this console does not know yet. Naming follows the API's: AI codes end in `.AiDetected`.
function inferSource(code: string, category: string): FindingSource {
  if (category === 'InconclusiveAnalysis') {
    return 'system'
  }

  return code.endsWith('.AiDetected') ? 'ai' : 'rules'
}

function fallbackTitle(source: FindingSource, knownCategoryLabel: string | undefined): string {
  if (source === 'system') {
    return 'Analysis safeguard triggered'
  }

  if (knownCategoryLabel === undefined) {
    return source === 'ai' ? 'Security finding (AI-assisted)' : 'Security finding'
  }

  return source === 'ai' ? `${knownCategoryLabel} (AI-assisted)` : `${knownCategoryLabel} detected`
}

// The API's own description is client-safe by contract (fixed text, never analysed content), so it is the best
// fallback for a code this console does not know.
function fallbackDescription(apiDescription: unknown): string {
  return typeof apiDescription === 'string' && apiDescription.trim() !== '' ? apiDescription : genericDescription
}

// The response is typed, but a newer or faulty API could send anything: never let a missing value become "undefined".
function asText(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/** "NewCategoryName" → "New category name". Used only for category names this console does not know. */
function humanize(value: string): string {
  const words = value.replace(/([a-z0-9])([A-Z])/g, '$1 $2').trim()
  if (words === '') {
    return 'Uncategorised'
  }

  return words.charAt(0).toUpperCase() + words.slice(1).toLowerCase()
}
