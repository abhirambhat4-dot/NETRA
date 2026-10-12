import type * as React from 'react'

/**
 * Ambient network behind the Command Home: a sparse node graph kept to the edges
 * so the centre stays clear, light travelling along a few routes, drifting
 * particles and one slow scan line. CSS only (cb-* and ch-* in index.css), so
 * reduced motion stops everything without JavaScript.
 */

type Pt = readonly [number, number]

// viewBox 1600 × 1000, sliced to cover the viewport
const N = {
  a: [80, 120], b: [250, 70], c: [190, 290], d: [60, 450], e: [230, 600], f: [100, 800], g: [300, 920],
  h: [520, 50], i: [800, 95], j: [1080, 45], k: [560, 955], l: [860, 920], m: [1100, 965],
  n: [1340, 80], o: [1520, 170], p: [1400, 320], q: [1540, 480], r: [1370, 640], s: [1500, 810], t: [1290, 910],
} satisfies Record<string, Pt>
type Id = keyof typeof N

const EDGES: [Id, Id][] = [
  ['a', 'b'], ['a', 'c'], ['b', 'c'], ['c', 'd'], ['d', 'e'], ['e', 'f'], ['f', 'g'], ['e', 'g'], ['b', 'h'],
  ['h', 'i'], ['i', 'j'], ['j', 'n'], ['g', 'k'], ['k', 'l'], ['l', 'm'], ['m', 't'], ['n', 'o'], ['n', 'p'],
  ['o', 'p'], ['p', 'q'], ['p', 'r'], ['q', 'r'], ['r', 's'], ['s', 't'], ['r', 't'],
]

const FLOWS: { via: Id[]; dur: number; begin: number; color: string; wide?: boolean }[] = [
  { via: ['a', 'c', 'd', 'e', 'g', 'k', 'l'], dur: 16, begin: 0, color: 'var(--tech-cyan)' },
  { via: ['o', 'p', 'r', 't', 'm'], dur: 13, begin: 4, color: 'var(--brand-violet)' },
  { via: ['b', 'h', 'i', 'j', 'n', 'p', 'q'], dur: 19, begin: 7, color: 'var(--tech-cyan)', wide: true },
  { via: ['f', 'g', 'k', 'l', 'm'], dur: 11, begin: 2, color: 'var(--brand-violet)', wide: true },
]

const PULSES: Id[] = ['c', 'p', 'k']

// Deterministic spread; the second half only shows from sm up to keep phones light.
const PARTICLES = Array.from({ length: 20 }, (_, i) => ({
  left: (i * 37 + 11) % 100,
  top: (i * 53 + 17) % 100,
  size: 1.5 + (i % 3) * 0.75,
  dur: 15 + (i % 5) * 3,
  delay: -((i * 2.3) % 18),
  drift: ((i % 4) - 1.5) * 10,
  opacity: i % 4 === 0 ? 0.8 : 0.45,
}))

const path = (ids: Id[]) => ids.map((id, i) => `${i ? 'L' : 'M'}${N[id][0]},${N[id][1]}`).join(' ')

export function CommandHomeBackdrop() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_70%_55%_at_50%_42%,rgb(29_78_216/0.14),transparent_70%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_40%_32%_at_12%_88%,rgb(56_217_255/0.06),transparent_70%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_40%_32%_at_88%_10%,rgb(79_124_255/0.07),transparent_70%)]" />
      <div className="netra-grid absolute inset-0 [mask-image:radial-gradient(ellipse_85%_75%_at_50%_45%,black_15%,transparent_80%)]" />

      <svg className="absolute inset-0 size-full opacity-75" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice">
        <g stroke="rgb(100 140 190)" strokeOpacity={0.16}>
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
            className={f.wide ? 'cb-flow hidden md:block' : 'cb-flow'}
            style={{ animationDuration: `${f.dur}s`, animationDelay: `${f.begin}s` }}
          />
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
            style={{ animationDelay: `${i * 1.9}s` }}
          />
        ))}

        {(Object.keys(N) as Id[]).map((id, i) => (
          <g key={id}>
            <circle cx={N[id][0]} cy={N[id][1]} r={4.5} fill="var(--background)" stroke="rgb(148 180 220)" strokeOpacity={0.3} />
            <circle cx={N[id][0]} cy={N[id][1]} r={1.6} fill="var(--primary)" className="cb-node" style={{ animationDelay: `${(i % 6) * 0.6}s` }} />
          </g>
        ))}
      </svg>

      {PARTICLES.map((p, i) => (
        <span
          key={i}
          className={i >= 10 ? 'ch-particle hidden sm:block' : 'ch-particle'}
          style={
            {
              left: `${p.left}%`,
              top: `${p.top}%`,
              width: p.size,
              height: p.size,
              '--ch-dur': `${p.dur}s`,
              '--ch-delay': `${p.delay}s`,
              '--ch-drift-x': `${p.drift}px`,
              '--ch-particle-opacity': p.opacity,
            } as React.CSSProperties
          }
        />
      ))}

      <div className="ch-scan" />

      {/* Vignette */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_75%_at_50%_45%,transparent_55%,var(--background)_100%)]" />
    </div>
  )
}
