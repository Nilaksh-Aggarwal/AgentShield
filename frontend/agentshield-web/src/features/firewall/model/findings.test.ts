import { describe, expect, it } from 'vitest'
import type { ThreatFinding } from '../api/analyzeInput'
import { presentAiParticipation } from './ai'
import { presentFinding, summariseReasons, type FindingSource } from './findings'

function finding(overrides: Partial<Record<keyof ThreatFinding, unknown>> = {}): ThreatFinding {
  return {
    code: 'InstructionOverride.IgnorePrevious',
    category: 'InstructionOverride',
    severity: 'High',
    confidence: 0.9,
    description: 'Attempts to override the AI’s instructions.',
    ...overrides,
  } as ThreatFinding
}

// Every finding code the API returns today, with the source the console must attribute it to.
const apiCodes: [string, string, FindingSource][] = [
  ['InstructionOverride.IgnorePrevious', 'InstructionOverride', 'rules'],
  ['InstructionOverride.DiscardContext', 'InstructionOverride', 'rules'],
  ['InstructionOverride.NewInstructions', 'InstructionOverride', 'rules'],
  ['RoleManipulation.ForgedRoleDelimiter', 'RoleManipulation', 'rules'],
  ['RoleManipulation.UnrestrictedPersona', 'RoleManipulation', 'rules'],
  ['RoleManipulation.AuthorityClaim', 'RoleManipulation', 'rules'],
  ['SecretExtraction.SystemPromptDisclosure', 'SecretExtraction', 'rules'],
  ['SecretExtraction.CredentialDisclosure', 'SecretExtraction', 'rules'],
  ['Obfuscation.EncodedThreat', 'Obfuscation', 'rules'],
  ['Obfuscation.MaskedThreat', 'Obfuscation', 'rules'],
  ['Obfuscation.UninspectableContent', 'Obfuscation', 'system'],
  ['InstructionOverride.AiDetected', 'InstructionOverride', 'ai'],
  ['RoleManipulation.AiDetected', 'RoleManipulation', 'ai'],
  ['SecretExtraction.AiDetected', 'SecretExtraction', 'ai'],
  ['Obfuscation.AiDetected', 'Obfuscation', 'ai'],
  ['InconclusiveAnalysis.AiAnalysisIncomplete', 'InconclusiveAnalysis', 'system'],
]

describe('presentFinding', () => {
  it.each(apiCodes)('describes %s and attributes it to its source', (code, category, source) => {
    const presentation = presentFinding(finding({ code, category }))

    expect(presentation).toMatchObject({ code, known: true, source })
    expect(presentation.title).not.toBe('')
    expect(presentation.recommendedAction).not.toBe('')
  })

  it('never presents a confidence as a percentage or probability', () => {
    const rule = presentFinding(finding({ confidence: 0.85 }))
    const ai = presentFinding(finding({ code: 'InstructionOverride.AiDetected', confidence: 0.85 }))

    expect(rule.confidence).toEqual({ label: 'Rule confidence (heuristic)', level: 'High' })
    expect(ai.confidence).toEqual({ label: 'AI-reported confidence (uncalibrated)', level: 'High' })
    expect(JSON.stringify([rule, ai])).not.toMatch(/%|probab/i)
  })

  it.each([
    [0.8, 'High'],
    [0.79, 'Moderate'],
    [0.6, 'Moderate'],
    [0.59, 'Low'],
    [0, 'Low'],
  ])('reads confidence %d as %s', (confidence, level) => {
    expect(presentFinding(finding({ confidence })).confidence?.level).toBe(level)
  })

  it.each([Number.NaN, -0.1, 1.01, Number.POSITIVE_INFINITY, '0.9', null])('drops an unusable confidence %j', (confidence) => {
    expect(presentFinding(finding({ confidence })).confidence).toBeNull()
  })

  it('shows no confidence for a safeguard, which is not an attack', () => {
    expect(presentFinding(finding({ code: 'InconclusiveAnalysis.AiAnalysisIncomplete', category: 'InconclusiveAnalysis' })).confidence).toBeNull()
  })

  it('gives an unknown code a generic presentation from its category and source', () => {
    expect(presentFinding(finding({ code: 'SecretExtraction.NewRule', category: 'SecretExtraction' }))).toMatchObject({
      known: false,
      title: 'Secret extraction detected',
      source: 'rules',
    })
    expect(presentFinding(finding({ code: 'RoleManipulation.Future.AiDetected', category: 'RoleManipulation' }))).toMatchObject({
      known: false,
      title: 'Role manipulation (AI-assisted)',
      source: 'ai',
    })
    expect(presentFinding(finding({ code: 'InconclusiveAnalysis.Other', category: 'InconclusiveAnalysis' }))).toMatchObject({
      title: 'Analysis safeguard triggered',
      source: 'system',
    })
    expect(presentFinding(finding({ code: 'NewCategory.Thing', category: 'NewCategoryName' })).categoryLabel).toBe('New category name')
  })

  it.each(['constructor', '__proto__', 'toString'])('treats the prototype key %j as an unknown code and category', (key) => {
    const presentation = presentFinding(finding({ code: key, category: key }))

    expect(presentation.known).toBe(false)
    expect(presentation.title).toBe('Security finding')
  })

  it('never renders a missing or mistyped field as the word "undefined" or "null"', () => {
    const presentation = presentFinding(finding({ code: undefined, category: 42, severity: null, description: undefined }))

    expect(JSON.stringify(presentation)).not.toMatch(/undefined|null|NaN|\[object/)
    expect(presentation.severity.label).toBe('Unknown')
    expect(presentation.categoryLabel).toBe('Uncategorised')
  })

  it('uses the API description only as the fallback for a code it does not know', () => {
    expect(presentFinding(finding({ code: 'InstructionOverride.Unknown', description: 'Fixed text from the API.' })).description).toBe('Fixed text from the API.')
    expect(presentFinding(finding({ description: 'Fixed text from the API.' })).description).not.toBe('Fixed text from the API.')
  })
})

describe('summariseReasons', () => {
  it('lists distinct titles, at most three, and counts the rest', () => {
    const findings = ['InstructionOverride.IgnorePrevious', 'RoleManipulation.ForgedRoleDelimiter', 'SecretExtraction.CredentialDisclosure', 'Obfuscation.EncodedThreat', 'Obfuscation.EncodedThreat']
      .map((code) => presentFinding(finding({ code, category: code.split('.')[0] })))

    const summary = summariseReasons(findings)

    expect(summary.titles).toHaveLength(3)
    expect(summary.more).toBe(1)
  })
})

describe('presentAiParticipation', () => {
  const present = (codes: string[], decision: string) =>
    presentAiParticipation(codes.map((code) => presentFinding(finding({ code, category: code.split('.')[0] }))), decision)

  it('reports an incomplete AI analysis without saying why', () => {
    const ai = present(['InconclusiveAnalysis.AiAnalysisIncomplete'], 'Review')

    expect(ai).toMatchObject({ state: 'incomplete', tone: 'warning' })
    expect(ai.description).toMatch(/held for review/)
  })

  it('counts AI findings and says the policy decided', () => {
    expect(present(['InstructionOverride.AiDetected'], 'Block').description).toMatch(/^It added one finding.*policy, not the AI/)
    expect(present(['InstructionOverride.AiDetected', 'SecretExtraction.AiDetected', 'InstructionOverride.IgnorePrevious'], 'Block')).toMatchObject({
      state: 'contributed',
      description: expect.stringMatching(/^It added 2 findings/) as unknown,
    })
  })

  it('mentions the Block skip only for a Block', () => {
    expect(present([], 'Block').description).toMatch(/skipped/)
    expect(present([], 'Allow').description).not.toMatch(/skipped/)
    expect(present(['InstructionOverride.IgnorePrevious'], 'Review').state).toBe('not-reported')
  })
})
