import type { ReactNode } from 'react'

interface SectionHeaderProps {
  title: ReactNode
  description?: ReactNode
  /** Short uppercase label above the title (e.g. the area a section belongs to). */
  eyebrow?: ReactNode
  actions?: ReactNode
  as?: 'h2' | 'h3'
  id?: string
}

/** Heading block for a section within a page (the page itself uses `PageHeader`). */
export function SectionHeader({ title, description, eyebrow, actions, as: Heading = 'h2', id }: SectionHeaderProps) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
      <div className="min-w-0 space-y-1">
        {eyebrow && <p className="text-xs font-semibold tracking-wider text-muted uppercase">{eyebrow}</p>}
        <Heading id={id} className="text-lg font-semibold tracking-tight text-foreground">
          {title}
        </Heading>
        {description && <p className="max-w-3xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}
