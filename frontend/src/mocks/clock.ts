/**
 * All mock timestamps are relative to page load so the demo always looks live.
 */
export const NOW = Math.floor(Date.now() / 1000) * 1000

export const MINUTE = 60_000
export const HOUR = 60 * MINUTE

export function minutesAgo(minutes: number): string {
  return new Date(NOW - minutes * MINUTE).toISOString()
}

/** Deterministic PRNG (mulberry32) — same "random" noise on every reload. */
export function seeded(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
