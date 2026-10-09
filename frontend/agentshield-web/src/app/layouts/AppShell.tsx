import { useEffect, useRef, type ReactNode } from 'react'
import { useLocation } from 'react-router'
import { SkipLink } from '@/shared/components/layout'
import { AppFooter } from './AppFooter'
import { AppHeader } from './AppHeader'

const MainContentId = 'main-content'

/**
 * Page chrome shared by every route and the route error view: skip link, header (banner + primary navigation), main
 * content, footer.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation()
  const mainRef = useRef<HTMLElement>(null)
  const previousPathname = useRef(pathname)

  // A client-side navigation does not move focus or announce a new page. Moving focus to the main region does both,
  // and the next Tab continues inside the new page. Not on first load (compared by path, so StrictMode's second effect
  // run does not count as a navigation).
  useEffect(() => {
    if (previousPathname.current !== pathname) {
      previousPathname.current = pathname
      mainRef.current?.focus()
    }
  }, [pathname])

  return (
    <div className="flex min-h-screen flex-col">
      <SkipLink targetId={MainContentId} />
      <AppHeader />
      {/* Focus target only (skip link, navigation), not an interactive control: no focus ring. */}
      <main
        id={MainContentId}
        ref={mainRef}
        tabIndex={-1}
        className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 focus:outline-none sm:px-6 lg:py-10"
      >
        {children}
      </main>
      <AppFooter />
    </div>
  )
}
