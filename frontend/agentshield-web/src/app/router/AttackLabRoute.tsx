import { lazy, Suspense } from 'react'

// The Attack Lab is a demonstration page, not part of the console's core: its own chunk keeps the main bundle small.
// React.lazy rather than the route's `lazy`, which would need a hydration fallback on a direct load of the page.
const AttackLabPage = lazy(() => import('@/features/attack-lab').then((module) => ({ default: module.AttackLabPage })))

/** The Attack Lab route, loaded on first visit. */
export function AttackLabRoute() {
  return (
    <Suspense fallback={<p className="text-sm text-muted">Loading the Attack Lab…</p>}>
      <AttackLabPage />
    </Suspense>
  )
}
