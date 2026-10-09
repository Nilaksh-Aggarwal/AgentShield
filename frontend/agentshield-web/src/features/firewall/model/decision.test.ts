import { describe, expect, it } from 'vitest'
import { presentDecision, presentRiskLevel, presentSeverity, riskBands } from './decision'

// Values an API (newer, faulty or tampered) could send that a plain object lookup would resolve to inherited members.
const prototypeKeys = ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']

describe('presentDecision', () => {
  it.each([
    ['Allow', 'Safe to forward', 'success'],
    ['Review', 'Hold for human review', 'warning'],
    ['Block', 'Do not forward to the agent', 'danger'],
  ])('presents %s with its action and tone', (decision, action, tone) => {
    expect(presentDecision(decision)).toMatchObject({ label: decision, action, tone, known: true })
  })

  it('never promises that an allowed input is harmless', () => {
    const { summary } = presentDecision('Allow')

    expect(summary).toMatch(/not a guarantee/i)
    expect(summary).not.toMatch(/\bsafe\b/i)
  })

  it.each(['Sanitize', 'allow', 'BLOCK', ' ', '', ...prototypeKeys])(
    'holds an unrecognised decision %j for review, never as safe',
    (decision) => {
      const presentation = presentDecision(decision)

      expect(presentation.known).toBe(false)
      expect(presentation.action).toBe('Hold for human review')
      expect(presentation.tone).toBe('warning')
      expect(presentation.label).not.toBe('')
    },
  )
})

describe('presentRiskLevel and presentSeverity', () => {
  it.each([
    ['Low', 'Low risk', 'success'],
    ['Medium', 'Medium risk', 'warning'],
    ['High', 'High risk', 'danger'],
    ['Critical', 'Critical risk', 'critical'],
  ])('presents risk level %s', (level, label, tone) => {
    expect(presentRiskLevel(level)).toEqual({ label, tone })
  })

  it.each(['Extreme', '', ...prototypeKeys])('shows an unknown risk level %j by name in a neutral tone', (level) => {
    const presentation = presentRiskLevel(level)

    expect(presentation.tone).toBe('neutral')
    expect(presentation.label).toBe(level.trim() === '' ? 'Unknown risk' : `${level} risk`)
  })

  it.each(['Severe', '', ...prototypeKeys])('shows an unknown severity %j by name in a neutral tone', (severity) => {
    const presentation = presentSeverity(severity)

    expect(presentation.tone).toBe('neutral')
    expect(presentation.label).toBe(severity.trim() === '' ? 'Unknown' : severity)
  })
})

describe('riskBands', () => {
  it('covers 0 to 100 without gaps or overlaps, with the bands the API documents', () => {
    expect(riskBands.map(({ level, min, max }) => [level, min, max])).toEqual([
      ['Low', 0, 29],
      ['Medium', 30, 69],
      ['High', 70, 89],
      ['Critical', 90, 100],
    ])
    riskBands.slice(1).forEach((band, index) => expect(band.min).toBe(riskBands[index]!.max + 1))
  })
})
