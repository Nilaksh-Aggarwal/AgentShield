import { isRouteErrorResponse, useRouteError } from 'react-router'
import { AppShell } from '@/app/layouts/AppShell'
import { isApiError } from '@/services/api'
import { DocumentTitle, PageHeader } from '@/shared/components/layout'
import { ButtonLink } from '@/shared/components/ui'

/**
 * Route-level error boundary, rendered in place of the root layout, so it brings the app chrome itself. Shows a safe
 * message only: raw errors and stack traces are never rendered (they are available in the browser console during
 * development).
 */
export function RouteErrorView() {
  const error = useRouteError()

  let message = 'Something went wrong while rendering this page.'
  let reference: string | undefined

  if (isRouteErrorResponse(error)) {
    message = error.status === 404 ? 'The page you requested does not exist.' : `The request failed (${error.status}).`
  } else if (isApiError(error)) {
    message = error.userMessage
    reference = error.correlationId
  }

  return (
    <AppShell>
      <DocumentTitle title="Error" />
      <section className="space-y-6" role="alert" aria-labelledby="route-error-heading">
        <PageHeader id="route-error-heading" title="Unexpected error" description={<p>{message}</p>} />
        {reference && (
          <p className="text-sm text-muted">
            Reference <code className="font-mono break-all">{reference}</code>
          </p>
        )}
        <ButtonLink to="/" variant="secondary">
          Return to overview
        </ButtonLink>
      </section>
    </AppShell>
  )
}
