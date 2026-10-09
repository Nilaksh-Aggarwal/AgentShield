import { describe, expect, it } from 'vitest'
import { parseRetryAfter } from './retryAfter'

const now = Date.UTC(2026, 9, 1, 12, 0, 0)

describe('parseRetryAfter', () => {
  it.each([
    ['1', 1],
    ['30', 30],
    [' 60 ', 60],
    ['999999999', 999_999_999],
  ])('reads delta-seconds %j', (value, seconds) => {
    expect(parseRetryAfter(value, now)).toBe(seconds)
  })

  it('reads an IMF-fixdate as the whole seconds until then, rounded up', () => {
    expect(parseRetryAfter('Thu, 01 Oct 2026 12:00:30 GMT', now)).toBe(30)
    expect(parseRetryAfter('Thu, 01 Oct 2026 12:01:00 GMT', now - 500)).toBe(61)
  })

  // D-16: these used to show "Try again in 0 seconds" or "Infinity seconds".
  it.each([
    ['0'],
    ['-5'],
    ['1.5'],
    ['1e3'],
    ['0x10'],
    ['1234567890'],
    ['9'.repeat(400)],
    ['soon'],
    [''],
    ['   '],
    ['2026-10-01T12:00:30Z'],
    ['Thu, 01 Oct 2026 11:59:00 GMT'],
    ['Thu, 01 Oct 2026 12:00:00 GMT'],
    ['thu, 01 oct 2026 12:00:30 gmt'],
  ])('ignores %j: no wait is shown rather than a wrong one', (value) => {
    expect(parseRetryAfter(value, now)).toBeUndefined()
  })

  it.each([null, undefined])('ignores a missing header (%j)', (value) => {
    expect(parseRetryAfter(value, now)).toBeUndefined()
  })
})
