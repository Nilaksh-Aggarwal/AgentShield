import type { ReactNode } from 'react'

interface EmptyStateProps {
  icon?: ReactNode
  title: ReactNode
  description?: ReactNode
  action?: ReactNode
  as?: 'h2' | 'h3'
}

/** What a view shows when it has nothing (yet): says why, and what to do next. Never placeholder numbers. */
export function EmptyState({ icon, title, description, action, as: Heading = 'h2' }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border bg-surface px-6 py-12 text-center">
      {icon && (
        <div className="flex size-10 items-center justify-center rounded-full bg-background text-muted">{icon}</div>
      )}
      <Heading className="text-base font-semibold text-foreground">{title}</Heading>
      {description && <div className="max-w-md space-y-2 text-sm text-muted">{description}</div>}
      {action && <div className="pt-1">{action}</div>}
    </div>
  )
}
