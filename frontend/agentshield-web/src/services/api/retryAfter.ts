// RFC 9110 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT" (the only HTTP-date form servers must send).
const imfFixdate = /^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/

/**
 * Seconds to wait from a `Retry-After` header: delta-seconds (up to 9 digits) or an IMF-fixdate. Returns `undefined`
 * for anything else and for a wait under one second, so the UI never shows "0" or an absurd number of seconds.
 */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | undefined {
  const text = value?.trim()
  if (!text) {
    return undefined
  }

  let seconds: number | undefined
  if (/^\d{1,9}$/.test(text)) {
    seconds = Number(text)
  } else if (imfFixdate.test(text)) {
    const date = Date.parse(text)
    seconds = Number.isNaN(date) ? undefined : Math.ceil((date - now) / 1000)
  }

  return seconds !== undefined && seconds >= 1 ? seconds : undefined
}
