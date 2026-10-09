import { ArrowRightIcon, Button } from '@/shared/components/ui'

interface ActivityPaginationProps {
  page: number
  totalPages: number
  onPage: (page: number) => void
  /** A page is loading: both buttons wait. */
  busy: boolean
}

export function ActivityPagination({ page, totalPages, onPage, busy }: ActivityPaginationProps) {
  return (
    <nav aria-label="Activity pages" className="flex items-center justify-between gap-3 border-t border-border px-4 py-3 sm:px-6">
      <Button variant="secondary" disabled={busy || page <= 1} onClick={() => onPage(page - 1)}>
        <ArrowRightIcon className="size-4 rotate-180" />
        Previous
      </Button>
      <p className="text-sm text-muted">
        Page <span className="tabular-nums">{page}</span> of <span className="tabular-nums">{Math.max(totalPages, 1)}</span>
      </p>
      <Button variant="secondary" disabled={busy || page >= totalPages} onClick={() => onPage(page + 1)}>
        Next
        <ArrowRightIcon className="size-4" />
      </Button>
    </nav>
  )
}
