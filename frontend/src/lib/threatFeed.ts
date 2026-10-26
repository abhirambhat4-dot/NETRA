// Dependency-free so it runs under `node --test` (tests/threatFeed.test.ts).

/**
 * ThreatFox indicators reach NETRA through the backend's manual sync (scripts/netra_threatfox_sync.py),
 * which stores them in threat_indicators with this source. The browser only reads what is stored, through
 * the existing GET /api/threat-intelligence; it never calls ThreatFox and never sees the ThreatFox key.
 */
export const THREATFOX_SOURCE = 'ThreatFox (abuse.ch)'

export interface ThreatFeedSummary {
  /** Indicators stored from this source, active and inactive (expired) alike. */
  total: number
  /** Latest ThreatFox last-seen among them, or null when none are stored. */
  latestSeenAt: string | null
}

/**
 * What the feed is, stated once: imported on demand from recent reports, never real-time monitoring. The stored
 * count includes expired (inactive) indicators; only active ones are matched, and the API reports no active count.
 */
export const THREAT_FEED_SCOPE =
  'Imported on demand by an administrator with the ThreatFox sync, from indicators reported to ThreatFox in the previous 1–7 days. Not real-time. The stored count includes expired (inactive) indicators: only active ones, reported within the expiry window, are used to match events, score risk and assess assets.'

export function threatFeedStatus(summary: ThreatFeedSummary): { title: string; description: string } {
  if (summary.total === 0) {
    return {
      title: 'No ThreatFox indicators stored yet',
      description: 'An administrator imports them by running the ThreatFox sync on the backend.',
    }
  }
  return {
    title: `${summary.total.toLocaleString('en-US')} ThreatFox ${summary.total === 1 ? 'indicator' : 'indicators'} stored (active and expired)`,
    description: THREAT_FEED_SCOPE,
  }
}
