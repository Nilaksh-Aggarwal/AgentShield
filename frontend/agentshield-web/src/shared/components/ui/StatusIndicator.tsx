import type { HTMLAttributes, ReactNode } from 'react'

export type StatusTone = 'ok' | 'warning' | 'down' | 'pending'

const dotClass: Record<StatusTone, string> = {
  ok: 'bg-success',
  warning: 'bg-warning',
  down: 'bg-danger',
  pending: 'bg-muted',
}

interface StatusIndicatorProps extends HTMLAttributes<HTMLSpanElement> {
  tone: StatusTone
  label: ReactNode
}

/**
 * The state of a live system component (e.g. the API) as a dot and a label. The label always states the status in
 * words; the dot only repeats it. Add `role="status"` where the caller wants changes announced.
 */
export function StatusIndicator({ tone, label, className = '', ...props }: StatusIndicatorProps) {
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1 text-sm whitespace-nowrap text-muted ${className}`}
      {...props}
    >
      <span className={`size-2 shrink-0 rounded-full ${dotClass[tone]}`} aria-hidden="true" />
      {label}
    </span>
  )
}
