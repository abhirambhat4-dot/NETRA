import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { HEALTH_REFRESH_MS, createPoller, type Schedule } from '../src/lib/healthPoller.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const settle = () => new Promise((resolve) => setTimeout(resolve, 0))

/** A schedule the test ticks by hand, recording how many timers are running. */
function fakeSchedule() {
  const running = new Set<() => void>()
  let started = 0
  const schedule: Schedule = (refresh) => {
    started++
    running.add(refresh)
    return () => running.delete(refresh)
  }
  return { schedule, tick: () => running.forEach((refresh) => refresh()), running: () => running.size, started: () => started }
}

/** A load whose calls the test resolves or rejects by hand. */
function manualLoad<T>() {
  const calls: Array<{ resolve: (value: T) => void; reject: (reason: unknown) => void }> = []
  const load = () => new Promise<T>((resolve, reject) => calls.push({ resolve, reject }))
  return { load, calls }
}

test('health refreshes on the same 15-second cycle as Live Tracking', () => {
  assert.equal(HEALTH_REFRESH_MS, 15_000)
  assert.match(source('../src/pages/LiveTrackingPage.tsx'), /const REFRESH_INTERVAL_MS = HEALTH_REFRESH_MS/)
  const hook = source('../src/hooks/useHealthPoll.ts')
  assert.match(hook, /window\.setInterval\(\(\) => \{\s+if \(document\.visibilityState === 'visible'\) refresh\(\)\s+\}, HEALTH_REFRESH_MS\)/)
  // Cleanup releases both the timer and the mutation listener.
  assert.match(hook, /window\.clearInterval\(id\)\s+window\.removeEventListener\(DATA_CHANGED_EVENT, refresh\)/)
})

test('several subscribers share one load and one timer', async () => {
  const { schedule, tick, running, started } = fakeSchedule()
  const { load, calls } = manualLoad<string>()
  const poller = createPoller(load, schedule)
  const seen: string[] = []
  const unsubscribeHeader = poller.subscribe(() => seen.push('header'))
  const unsubscribeSidebar = poller.subscribe(() => seen.push('sidebar'))
  const unsubscribeLive = poller.subscribe(() => seen.push('live'))
  assert.equal(calls.length, 1, 'one initial load, not one per subscriber')
  assert.equal(started(), 1)
  assert.equal(running(), 1)
  assert.equal(poller.getSnapshot(), undefined, 'pending until the first load answers')

  calls[0].resolve('reading 1')
  await settle()
  assert.equal(poller.getSnapshot(), 'reading 1')
  assert.deepEqual(seen, ['header', 'sidebar', 'live'])

  tick()
  tick() // A tick while a load is in flight does not start a second one.
  assert.equal(calls.length, 2)
  calls[1].resolve('reading 2')
  await settle()
  assert.equal(poller.getSnapshot(), 'reading 2')

  unsubscribeHeader()
  unsubscribeSidebar()
  assert.equal(running(), 1, 'still polling while Live Tracking is mounted')
  unsubscribeLive()
})

test('the last unsubscribe stops the timer, clears the reading and ignores a late answer', async () => {
  const { schedule, tick, running } = fakeSchedule()
  const { load, calls } = manualLoad<string>()
  const poller = createPoller(load, schedule)
  const unsubscribe = poller.subscribe(() => undefined)
  calls[0].resolve('first')
  await settle()
  tick()
  unsubscribe()
  assert.equal(running(), 0, 'timer released')
  assert.equal(poller.getSnapshot(), undefined, 'a later mount starts from the loading state again')
  calls[1].resolve('late')
  await settle()
  assert.equal(poller.getSnapshot(), undefined, 'a load that settles after cleanup is ignored')
  poller.refresh()
  assert.equal(calls.length, 2, 'no loads without subscribers')
  unsubscribe() // A second call is harmless.
  assert.equal(running(), 0)

  // Resubscribing starts a fresh cycle.
  const again = poller.subscribe(() => undefined)
  assert.equal(calls.length, 3)
  assert.equal(running(), 1)
  again()
})

test('a failed load keeps the last reading; the next tick tries again', async () => {
  const { schedule, tick } = fakeSchedule()
  const { load, calls } = manualLoad<string>()
  const poller = createPoller(load, schedule)
  const unsubscribe = poller.subscribe(() => undefined)
  calls[0].resolve('healthy')
  await settle()
  tick()
  calls[1].reject(new Error('network'))
  await settle()
  assert.equal(poller.getSnapshot(), 'healthy')
  tick()
  assert.equal(calls.length, 3, 'the failed load did not leave polling stuck')
  calls[2].resolve('recovered')
  await settle()
  assert.equal(poller.getSnapshot(), 'recovered')
  unsubscribe()
})
