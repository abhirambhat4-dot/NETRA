import { useSyncExternalStore } from 'react'
import { HEALTH_REFRESH_MS, createPoller } from '@/lib/healthPoller'
import type { HealthOutcome } from '@/lib/workspaceStatus'
import { DATA_CHANGED_EVENT, dashboardService } from '@/services'
import { USE_MOCKS } from '@/services/http'

/** Demo data reports the mock component list; the live API reports its two raw health checks. */
export type HealthReading =
  | { mode: 'demo'; components: ReadonlyArray<{ status: string }> }
  | { mode: 'live'; checks: { api: HealthOutcome; database: HealthOutcome } }

const healthPoller = createPoller<HealthReading>(
  async () =>
    USE_MOCKS
      ? { mode: 'demo', components: await dashboardService.getSystemHealth() }
      : { mode: 'live', checks: await dashboardService.getHealthChecks() },
  (refresh) => {
    // Hidden tabs do not poll; mutations refresh at once, as useQuery does.
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') refresh()
    }, HEALTH_REFRESH_MS)
    window.addEventListener(DATA_CHANGED_EVENT, refresh)
    return () => {
      window.clearInterval(id)
      window.removeEventListener(DATA_CHANGED_EVENT, refresh)
    }
  },
)

/** One health reading shared by the header, the sidebar and Live Tracking, refreshed every 15 seconds. */
export function useHealthPoll(): HealthReading | undefined {
  return useSyncExternalStore(healthPoller.subscribe, healthPoller.getSnapshot)
}
