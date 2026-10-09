import type { HTMLAttributes } from 'react'
import type { Tone } from './tone'

// Class strings are written out in full so Tailwind can find them when scanning the source.
const toneClass: Record<Tone, { frame: string; fill: string }> = {
  neutral: { frame: 'border-border text-muted', fill: 'bg-background' },
  info: { frame: 'border-primary/30 text-primary', fill: 'bg-primary/10' },
  success: { frame: 'border-success/30 text-success', fill: 'bg-success/10' },
  warning: { frame: 'border-warning/30 text-warning', fill: 'bg-warning/10' },
  danger: { frame: 'border-danger/30 text-danger', fill: 'bg-danger/10' },
  critical: { frame: 'border-danger text-surface', fill: 'bg-danger' },
}

const sizeClass = {
  sm: 'gap-1 px-2 py-0.5 text-xs',
  md: 'gap-1.5 px-3 py-1 text-sm',
} as const

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: Tone
  size?: keyof typeof sizeClass
  /**
   * The badge sits on a background already tinted in a tone colour: fill it with the surface colour instead of a second
   * tint, which would stack and lower the text contrast.
   */
  onTint?: boolean
}

/**
 * A compact label for a status or classification (decision, severity, finding source). Colour is never the only
 * signal: the text always says what the badge means.
 */
export function Badge({ tone = 'neutral', size = 'sm', onTint = false, className = '', ...props }: BadgeProps) {
  const { frame, fill } = toneClass[tone]
  const background = onTint && tone !== 'critical' ? 'bg-surface' : fill

  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold whitespace-nowrap ${frame} ${background} ${sizeClass[size]} ${className}`}
      {...props}
    />
  )
}
