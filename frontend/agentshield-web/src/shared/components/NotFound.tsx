import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { ButtonLink } from '@/shared/components/ui'

export function NotFound() {
  return (
    <section className="space-y-6" aria-labelledby="not-found-heading">
      <DocumentTitle title="Page not found" />
      <PageHeader id="not-found-heading" title="Page not found" description={<p>The page you requested does not exist.</p>} />
      <ButtonLink to="/" variant="secondary">
        Return to overview
      </ButtonLink>
    </section>
  )
}
