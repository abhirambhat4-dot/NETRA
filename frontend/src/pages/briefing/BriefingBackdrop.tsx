import { usePrefersReducedMotion } from './reducedMotion'

/**
 * Quiet network backdrop for the security briefing: a sparse node graph at
 * the edges of the viewport with data moving along a few routes. Fixed, so it
 * stays put while the briefing scrolls. Animations reuse the login `cb-*` set.
 */

type Pt = readonly [number, number]

// viewBox 1600 × 1000, sliced to cover the viewport
const N = {
  a: [90, 140], b: [260, 90], c: [210, 300], d: [70, 470], e: [250, 610], f: [120, 820], g: [330, 900],
  h: [560, 60], i: [820, 110], j: [1060, 55], k: [640, 960], l: [930, 915],
  m: [1330, 90], n: [1510, 180], o: [1380, 330], p: [1530, 500], q: [1350, 640], r: [1490, 820], s: [1230, 920],
} satisfies Record<string, Pt>
type Id = keyof typeof N

const EDGES: [Id, Id][] = [
  ['a', 'b'], ['a', 'c'], ['b', 'c'], ['c', 'd'], ['d', 'e'], ['e', 'f'], ['f', 'g'], ['e', 'g'], ['b', 'h'],
  ['h', 'i'], ['i', 'j'], ['j', 'm'], ['g', 'k'], ['k', 'l'], ['l', 's'], ['m', 'n'], ['m', 'o'], ['n', 'o'],
  ['o', 'p'], ['p', 'q'], ['o', 'q'], ['q', 'r'], ['r', 's'], ['q', 's'],
]

const FLOWS: { via: Id[]; dur: number; begin: number; color: string; dense?: boolean }[] = [
  { via: ['a', 'c', 'd', 'e', 'g', 'k', 'l'], dur: 16, begin: 0, color: 'var(--tech-cyan)' },
  { via: ['n', 'o', 'q', 's', 'l'], dur: 12, begin: 3, color: 'var(--primary)' },
  { via: ['b', 'h', 'i', 'j', 'm', 'o', 'p'], dur: 18, begin: 6, color: 'var(--tech-cyan)', dense: true },
  { via: ['f', 'g', 'k'], dur: 9, begin: 2, color: 'var(--primary)', dense: true },
]

const PULSES: Id[] = ['c', 'o', 'g']

const path = (ids: Id[]) => ids.map((id, i) => `${i ? 'L' : 'M'}${N[id][0]},${N[id][1]}`).join(' ')

export function BriefingBackdrop() {
  const reduced = usePrefersReducedMotion()

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_45%_at_50%_0%,rgb(79_140_255/0.12),transparent_70%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_35%_30%_at_90%_70%,rgb(34_211_238/0.05),transparent_70%)]" />
      <div className="netra-grid absolute inset-0 [mask-image:radial-gradient(ellipse_90%_80%_at_50%_40%,black_20%,transparent_85%)]" />

      <svg className="absolute inset-0 size-full opacity-70" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice">
        <g stroke="rgb(148 163 184)" strokeOpacity={0.12}>
          {EDGES.map(([a, b]) => (
            <line key={`${a}${b}`} x1={N[a][0]} y1={N[a][1]} x2={N[b][0]} y2={N[b][1]} />
          ))}
        </g>

        {FLOWS.map((f, i) => (
          <path
            key={`flow-${i}`}
            d={path(f.via)}
            fill="none"
            stroke={f.color}
            strokeWidth={1.2}
            strokeLinecap="round"
            pathLength={1000}
            className={f.dense ? 'cb-flow hidden md:block' : 'cb-flow'}
            style={{ animationDuration: `${f.dur}s`, animationDelay: `${f.begin}s` }}
          />
        ))}

        {!reduced &&
          FLOWS.map((f, i) => (
            <circle key={`pkt-${i}`} r={2} fill={f.color} className={f.dense ? 'hidden md:block' : undefined}>
              <animateMotion dur={`${f.dur}s`} begin={`${f.begin}s`} repeatCount="indefinite" path={path(f.via)} />
              <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.08;0.92;1" dur={`${f.dur}s`} begin={`${f.begin}s`} repeatCount="indefinite" />
            </circle>
          ))}

        {PULSES.map((id, i) => (
          <circle
            key={`pulse-${id}`}
            cx={N[id][0]}
            cy={N[id][1]}
            r={6}
            fill="none"
            stroke="var(--primary)"
            strokeWidth={1}
            className="cb-pulse"
            style={{ animationDelay: `${i * 1.8}s` }}
          />
        ))}

        {(Object.keys(N) as Id[]).map((id, i) => (
          <g key={id}>
            <circle cx={N[id][0]} cy={N[id][1]} r={4.5} fill="var(--background)" stroke="rgb(148 163 184)" strokeOpacity={0.3} />
            <circle cx={N[id][0]} cy={N[id][1]} r={1.6} fill="var(--primary)" className="cb-node" style={{ animationDelay: `${(i % 6) * 0.6}s` }} />
          </g>
        ))}
      </svg>

      {/* Vignette */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_75%_at_50%_45%,transparent_50%,rgb(3_4_7/0.85)_100%)]" />
    </div>
  )
}
