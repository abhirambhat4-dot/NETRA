// Dependency-free so it runs under `node --test`.

export const REGISTRATION_CLOSED_MESSAGE =
  'Self-registration is turned off for this NETRA deployment. Ask a NETRA administrator to create your account.'
export const DUPLICATE_ACCOUNT_MESSAGE = 'An account with this email already exists.'
export const REGISTRATION_FAILED_MESSAGE = 'Unable to create your account right now. Please check your details and try again.'

/** Message for a failed registration, from the HTTP status (null when no response arrived). */
export function registerFailureMessage(status: number | null): string {
  // 403: the API has ALLOW_PUBLIC_REGISTRATION off; the reply is the same for every email.
  if (status === 403) return REGISTRATION_CLOSED_MESSAGE
  if (status === 409) return DUPLICATE_ACCOUNT_MESSAGE
  return REGISTRATION_FAILED_MESSAGE
}
