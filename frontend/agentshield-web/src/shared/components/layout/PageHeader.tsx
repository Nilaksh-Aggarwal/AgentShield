import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: ReactNode
  description?: ReactNode
  /** Short uppercase label above the title. */
  eyebrow?: ReactNode
  actions?: ReactNode
  /** ID of the `h1`, for `aria-labelledby` on the page's section. */
  id?: string
}

/** The one `h1` of a page, with its summary and page-level actions. */
export function PageHeader({ title, description, eyebrow, actions, id }: PageHeaderProps) {
  return (
    <header className="flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0 space-y-2">
        {eyebrow && <p className="text-xs font-semibold tracking-wider text-primary uppercase">{eyebrow}</p>}
        <h1 id={id} className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
          {title}
        </h1>
        {description && <div className="max-w-3xl space-y-2 text-muted">{description}</div>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </header>
  )
}
