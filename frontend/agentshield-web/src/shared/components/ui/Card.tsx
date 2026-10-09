import type { HTMLAttributes, ReactNode } from 'react'

interface CardProps extends HTMLAttributes<HTMLElement> {
  /** `section` (with a heading) for a landmark-worthy block, `article` for a self-contained item, `div` otherwise. */
  as?: 'div' | 'section' | 'article'
  /** Inner padding; use `none` when the card is split into bordered parts (header, body, table, footer). */
  padding?: 'none' | 'md'
}

/** A bordered surface that groups related content. */
export function Card({ as: Component = 'div', padding = 'md', className = '', ...props }: CardProps) {
  return (
    <Component
      className={`rounded-lg border border-border bg-surface shadow-xs ${padding === 'md' ? 'p-4 sm:p-6' : ''} ${className}`}
      {...props}
    />
  )
}

interface CardHeaderProps {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  /** Heading level inside the page outline (cards on a page are usually `h2`). */
  as?: 'h2' | 'h3'
  id?: string
}

/** Title row of a `padding="none"` card, separated from the content below by a border. */
export function CardHeader({ title, description, actions, as: Heading = 'h2', id }: CardHeaderProps) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-border px-4 py-3 sm:px-6">
      <div className="min-w-0 space-y-0.5">
        <Heading id={id} className="text-sm font-semibold text-foreground">
          {title}
        </Heading>
        {description && <p className="text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}
