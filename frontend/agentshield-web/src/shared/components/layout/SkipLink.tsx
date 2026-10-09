/** First focusable element on every page: lets keyboard users jump past the header to the page content. */
export function SkipLink({ targetId }: { targetId: string }) {
  return (
    <a
      href={`#${targetId}`}
      className="sr-only text-sm font-semibold text-foreground no-underline focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:border focus:border-border focus:bg-surface focus:px-4 focus:py-2 focus:shadow-lg"
    >
      Skip to main content
    </a>
  )
}
