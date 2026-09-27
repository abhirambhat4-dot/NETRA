/**
 * First-run security briefing flag.
 * MOCK — stored per browser in localStorage until the backend owns user
 * preferences. Storage can be unavailable (private mode, blocked site data),
 * so every access is guarded and a failure simply shows the briefing again.
 */

const KEY = 'netra.briefing.completed'

export function hasCompletedBriefing(): boolean {
  try {
    return window.localStorage.getItem(KEY) === '1'
  } catch {
    return false
  }
}

export function markBriefingCompleted(): void {
  try {
    window.localStorage.setItem(KEY, '1')
  } catch {
    // Non-critical: the briefing will be offered again next sign-in.
  }
}
