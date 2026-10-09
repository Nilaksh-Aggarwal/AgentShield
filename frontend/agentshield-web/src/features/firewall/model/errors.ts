import { isApiError } from '@/services/api'

export interface AnalysisErrorPresentation {
  title: string
  description: string
  /** Correlation ID for support, when the API or client provided one. */
  reference?: string
  /** Only when the API sent `Retry-After`. */
  retryAfterSeconds?: number
}

// Every failure means no decision was made: the input has not been checked.
const notChecked = 'No decision was made, so treat the input as not yet checked.'

/**
 * A failed analysis in plain language. Uses only the status, the client's own error kind and `Retry-After`; server text
 * is never shown here (field-level validation messages are shown next to the input instead).
 */
export function presentAnalysisError(error: unknown): AnalysisErrorPresentation {
  if (!isApiError(error)) {
    return { title: 'AgentShield couldn’t complete the analysis', description: `Something unexpected went wrong. ${notChecked}` }
  }

  const reference = error.correlationId
  switch (error.kind) {
    case 'network':
      return { title: 'Can’t reach the AgentShield API', description: `Check that the API is running, then try again. ${notChecked}`, reference }
    case 'timeout':
      return { title: 'The analysis took too long', description: `No answer arrived in time. Try again. ${notChecked}`, reference }
    case 'aborted':
      return { title: 'The analysis was cancelled', description: notChecked, reference }
    case 'invalid-response':
      return {
        title: 'Unexpected response from the API',
        description: `The API answered in a form this console does not understand. ${notChecked}`,
        reference,
      }
    case 'http':
      return { ...presentHttpError(error.status ?? 0, error.retryAfterSeconds), reference }
  }
}

function presentHttpError(status: number, retryAfterSeconds: number | undefined): Omit<AnalysisErrorPresentation, 'reference'> {
  switch (status) {
    case 400:
      return { title: 'The request could not be read', description: `The API could not read the request. Reload the page and try again. ${notChecked}` }
    case 401:
      return {
        title: 'Authentication required',
        description: `The API did not accept this console’s credentials, so nothing was analysed. ${notChecked}`,
      }
    case 403:
      return {
        title: 'You don’t have permission to analyze inputs',
        description: `This client is signed in but not allowed to submit inputs for analysis. ${notChecked}`,
      }
    case 422:
      return { title: 'Input validation failed', description: 'Fix the input as described next to the text box, then try again.' }
    case 429:
      return {
        title: 'Analysis temporarily rate limited',
        description:
          retryAfterSeconds === undefined
            ? `Too many analyses in a short time. Wait a moment, then try again. ${notChecked}`
            : `Too many analyses in a short time. Try again in ${retryAfterSeconds} ${retryAfterSeconds === 1 ? 'second' : 'seconds'}. ${notChecked}`,
        retryAfterSeconds,
      }
    default:
      return status >= 500
        ? {
            title: 'AgentShield couldn’t complete the analysis',
            description: `The server could not finish the analysis. ${notChecked} If it keeps happening, quote the reference below.`,
          }
        : { title: 'The request could not be processed', description: `The API refused the request. ${notChecked}` }
  }
}
