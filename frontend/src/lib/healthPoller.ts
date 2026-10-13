/**
 * A shared, deduplicated polling store: however many components read it, one load runs per tick.
 * Polling starts with the first subscriber and stops (timers released, reading cleared) when the
 * last one leaves. Import-free so tests/healthPoller.test.ts can drive it with a fake schedule.
 */

/** Health is re-read on the same cycle as Live Tracking. */
export const HEALTH_REFRESH_MS = 15_000

/** Starts the periodic triggers that call `refresh`; returns the function that stops them. */
export type Schedule = (refresh: () => void) => () => void

export interface Poller<T> {
  subscribe(listener: () => void): () => void
  /** The latest reading, or undefined until the first load succeeds. */
  getSnapshot(): T | undefined
  refresh(): void
}

export function createPoller<T>(load: () => Promise<T>, schedule: Schedule): Poller<T> {
  const listeners = new Set<() => void>()
  let snapshot: T | undefined
  let stop: (() => void) | null = null
  let inflight = false
  // Bumped when polling stops, so a load that settles afterwards is ignored.
  let generation = 0

  const refresh = () => {
    if (inflight || listeners.size === 0) return
    inflight = true
    const current = generation
    load()
      .then(
        (value) => {
          if (current !== generation) return
          snapshot = value
          listeners.forEach((listener) => listener())
        },
        // A failed load keeps the last reading, as the per-component queries it replaces did.
        () => undefined,
      )
      .finally(() => {
        if (current === generation) inflight = false
      })
  }

  return {
    subscribe(listener) {
      listeners.add(listener)
      if (listeners.size === 1) {
        refresh()
        stop = schedule(refresh)
      }
      return () => {
        if (!listeners.delete(listener) || listeners.size > 0) return
        stop?.()
        stop = null
        generation++
        inflight = false
        snapshot = undefined
      }
    },
    getSnapshot: () => snapshot,
    refresh,
  }
}
