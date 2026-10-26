import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { THREATFOX_SOURCE, THREAT_FEED_SCOPE, threatFeedStatus } from '../src/lib/threatFeed.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

test('the frontend reads the same ThreatFox source the backend sync writes', () => {
  assert.equal(THREATFOX_SOURCE, 'ThreatFox (abuse.ch)')
  assert.match(source('../../backend/app/services/threatfox.py'), /^THREATFOX_SOURCE = "ThreatFox \(abuse\.ch\)"$/m)
})

test('feed status: empty and stored states', () => {
  assert.deepEqual(threatFeedStatus({ total: 0, latestSeenAt: null }), {
    title: 'No ThreatFox indicators stored yet',
    description: 'An administrator imports them by running the ThreatFox sync on the backend.',
  })
  assert.equal(threatFeedStatus({ total: 1, latestSeenAt: '2026-10-23T10:00:00Z' }).title, '1 ThreatFox indicator stored (active and expired)')
  assert.equal(threatFeedStatus({ total: 1102, latestSeenAt: '2026-10-23T10:00:00Z' }).title, '1,102 ThreatFox indicators stored (active and expired)')
  assert.equal(threatFeedStatus({ total: 3, latestSeenAt: null }).description, THREAT_FEED_SCOPE)
})

test('the stored count is not presented as the set of indicators used for matching', () => {
  // The API counts active and expired indicators together; only active ones are matched.
  assert.match(THREAT_FEED_SCOPE, /stored count includes expired \(inactive\) indicators/)
  assert.match(THREAT_FEED_SCOPE, /only active ones, reported within the expiry window, are used to match events/)
  assert.doesNotMatch(THREAT_FEED_SCOPE, /NETRA uses them to match/)
})

test('the feed is described as an on-demand import of recent reports, never as real-time', () => {
  assert.match(THREAT_FEED_SCOPE, /Imported on demand/)
  assert.match(THREAT_FEED_SCOPE, /previous 1–7 days/)
  assert.match(THREAT_FEED_SCOPE, /Not real-time\./)
  const card = source('../src/pages/LiveTrackingPage.tsx')
  const feed = card.slice(card.indexOf('function ThreatFeedCard('), card.indexOf('/** Shown while the collector is idle'))
  assert.doesNotMatch(feed.replace('Not real-time', ''), /real-time|live feed|streaming/i)
})

test('Live Tracking reads stored ThreatFox indicators through the existing API, alongside its existing panels', () => {
  const live = source('../src/pages/LiveTrackingPage.tsx')
  assert.match(live, /useQuery\('live-threatfox-feed', \(\) => threatFeedService\.summary\(THREATFOX_SOURCE\)\)/)
  assert.match(live, /const reloads = \[collector\.reload, incidents\.reload, events\.reload, threatFeed\.reload\]/)
  assert.match(live, /<ThreatFeedCard summary=\{threatFeed\.data\} error=\{threatFeed\.error\} onRetry=\{threatFeed\.reload\} \/>/)
  // Existing panels are unchanged.
  for (const title of ['Active incidents', 'Incoming event severity', 'Unlinked high and critical events', 'Recent collector activity']) {
    assert.match(live, new RegExp(`title="${title}"`), title)
  }
  const services = source('../src/services/index.ts')
  const summary = services.slice(services.indexOf('export const threatFeedService'), services.indexOf('export const threatIntelService'))
  assert.match(summary, /http\.get<BackendThreatIndicatorPage>\('\/threat-intelligence', \{\s+source,\s+sortBy: 'lastSeen',\s+sortOrder: 'desc',\s+page: 1,\s+pageSize: 1,\s+\}\)/)
  assert.match(summary, /if \(USE_MOCKS\) throw new Error/)
})

test('the ThreatFox key and the ThreatFox API never appear in frontend code', () => {
  const root = fileURLToPath(new URL('../src', import.meta.url))
  const files: string[] = []
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name)
      if (statSync(path).isDirectory()) walk(path)
      else if (/\.(ts|tsx)$/.test(name)) files.push(path)
    }
  }
  walk(root)
  assert.ok(files.length > 50)
  for (const file of files) {
    const text = readFileSync(file, 'utf8')
    assert.doesNotMatch(text, /THREATFOX_AUTH_KEY|Auth-Key|threatfox-api\.abuse\.ch/, file)
  }
})
