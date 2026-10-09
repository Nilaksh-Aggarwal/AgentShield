import type { Tone } from '@/shared/components/ui'
import { riskBands } from '../model'

// Class strings are written out in full so Tailwind can find them when scanning the source.
const bandClass: Record<Tone, string> = {
  neutral: 'bg-muted',
  info: 'bg-primary',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  critical: 'bg-danger',
}

const scaleSize = 101 // scores 0 to 100 inclusive

interface RiskMeterProps {
  /** Score from the API (0–100). */
  score: number
  /** Level from the API; the band it names is highlighted. */
  level: string
}

/**
 * The API's risk score on the API's documented level scale. Visual aid only (hidden from assistive technology): the
 * level and score are always stated in text next to it, and the legend below it is readable text.
 */
export function RiskMeter({ score, level }: RiskMeterProps) {
  const position = ((Math.min(100, Math.max(0, score)) + 0.5) / scaleSize) * 100

  return (
    <div className="space-y-2">
      <div className="relative pt-1.5 pb-1" aria-hidden="true">
        <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full">
          {riskBands.map((band) => (
            <div
              key={band.level}
              className={`h-full ${bandClass[band.tone]} ${band.level === level ? '' : 'opacity-25'}`}
              style={{ width: `${((band.max - band.min + 1) / scaleSize) * 100}%` }}
            />
          ))}
        </div>
        <div
          className="absolute top-0 h-5.5 w-1.5 -translate-x-1/2 rounded-full bg-foreground ring-2 ring-surface"
          style={{ left: `${position}%` }}
        />
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
        {riskBands.map((band) => {
          const current = band.level === level
          return (
            <li key={band.level} className={`flex items-center gap-1.5 ${current ? 'font-semibold text-foreground' : ''}`}>
              <span className={`size-2 rounded-full ${bandClass[band.tone]}`} aria-hidden="true" />
              {band.level} {band.min}–{band.max}
              {current && <span className="sr-only"> (this input)</span>}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
