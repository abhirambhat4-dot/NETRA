import { useMemo } from 'react'

/**
 * Animated, abstract security-intelligence backdrop for the login gateway.
 * Pure SVG + CSS / SMIL — no JS animation loop. Nodes sit around the edges
 * of the viewport; the centre is masked so the login card stays readable.
 * Layers marked `dense` only render from md upward (tablet/desktop).
 */

type Pt = readonly [number, number]

// viewBox 1600 × 1000, sliced to cover the viewport
const N = {
  a: [180, 160], b: [360, 110], c: [520, 220], d: [250, 330], e: [430, 390], f: [120, 520],
  g: [330, 570], h: [480, 650], i: [200, 790], j: [400, 860], k: [590, 910], l: [560, 70],
  y: [800, 70], aa: [680, 175], ab: [925, 190], z: [800, 945], ac: [700, 835], ad: [915, 850],
  m: [1080, 90], n: [1260, 150], o: [1440, 105], p: [1150, 310], q: [1360, 330], r: [1500, 480],
  s: [1230, 530], t: [1420, 670], u: [1110, 710], v: [1300, 820], w: [1480, 890], x: [1020, 905],
} satisfies Record<string, Pt>
type Id = keyof typeof N

const EDGES: [Id, Id][] = [
  ['a', 'b'], ['b', 'c'], ['a', 'd'], ['d', 'e'], ['c', 'e'], ['b', 'l'], ['l', 'y'], ['d', 'f'], ['f', 'g'],
  ['g', 'e'], ['g', 'h'], ['h', 'j'], ['i', 'j'], ['f', 'i'], ['j', 'k'], ['k', 'z'], ['h', 'k'], ['y', 'aa'],
  ['y', 'ab'], ['aa', 'c'], ['ab', 'm'], ['y', 'm'], ['z', 'ac'], ['z', 'ad'], ['ac', 'k'], ['ad', 'x'],
  ['m', 'n'], ['n', 'o'], ['m', 'p'], ['n', 'p'], ['p', 'q'], ['o', 'q'], ['q', 'r'], ['p', 's'], ['s', 'q'],
  ['r', 't'], ['s', 't'], ['s', 'u'], ['u', 'v'], ['t', 'v'], ['v', 'w'], ['u', 'x'], ['x', 'z'], ['t', 'w'],
]

/** Attack / data paths that particles travel along. */
const ROUTES: { via: Id[]; dur: number; begin: number; tone: 'primary' | 'violet' | 'critical' }[] = [
  { via: ['a', 'd', 'e', 'g', 'h', 'k', 'z'], dur: 14, begin: 0, tone: 'primary' },
  { via: ['o', 'q', 'r', 't', 'w'], dur: 11, begin: 2, tone: 'primary' },
  { via: ['y', 'm', 'p', 's', 'u', 'x'], dur: 13, begin: 5, tone: 'violet' },
  { via: ['b', 'c', 'aa', 'y', 'ab', 'm', 'n'], dur: 15, begin: 3, tone: 'primary' },
  { via: ['i', 'j', 'k', 'ac', 'z', 'ad', 'x', 'u'], dur: 16, begin: 7, tone: 'violet' },
  { via: ['f', 'g', 'e', 'c'], dur: 8, begin: 1, tone: 'critical' },
  { via: ['n', 'p', 's', 't'], dur: 9, begin: 6, tone: 'critical' },
]

const LABELS: { at: Id; dx: number; dy: number; text: string; dense?: boolean }[] = [
  { at: 'a', dx: 12, dy: -10, text: 'DETECTION' },
  { at: 'e', dx: 22, dy: 4, text: 'ANALYSIS · 0.87' },
  { at: 'q', dx: 12, dy: -10, text: 'RISK 91/100' },
  { at: 'y', dx: 12, dy: -8, text: 'NETWORK 10.0.0.0/24' },
  { at: 'u', dx: 14, dy: -12, text: 'ASSET db-prod-01' },
  { at: 'j', dx: 12, dy: 16, text: 'EVENT EVT-88141' },
  { at: 't', dx: 14, dy: 16, text: 'THREAT T1110' },
  { at: 'z', dx: 12, dy: 16, text: 'CONTAINMENT READY', dense: true },
  { at: 'n', dx: 10, dy: -12, text: 'ENCRYPTED · TLS 1.3', dense: true },
  { at: 'i', dx: 12, dy: 4, text: 'SURICATA', dense: true },
  { at: 'r', dx: -76, dy: -12, text: 'ML DETECTOR', dense: true },
]

const PULSES: { at: Id; color: string; delay: number }[] = [
  { at: 'e', color: 'var(--sev-critical)', delay: 0 },
  { at: 'p', color: 'var(--sev-high)', delay: 1.6 },
  { at: 't', color: 'var(--sev-critical)', delay: 3.1 },
  { at: 'h', color: 'var(--sev-medium)', delay: 4.4 },
  { at: 'ab', color: 'var(--primary)', delay: 2.4 },
]

const ALERTS: { at: Id; dx: number; dy: number; text: string; color: string; delay: number }[] = [
  { at: 'd', dx: 14, dy: 22, text: 'SSH BRUTE FORCE · CRITICAL', color: 'var(--sev-critical)', delay: 0 },
  { at: 's', dx: -196, dy: 26, text: 'ANOMALY · BEACONING 93%', color: 'var(--sev-high)', delay: 4 },
  { at: 'w', dx: -210, dy: -26, text: 'POLICY · TLS 1.0 SESSION', color: 'var(--sev-medium)', delay: 8 },
]

const path = (ids: Id[]) => ids.map((id, i) => `${i ? 'L' : 'M'}${N[id][0]},${N[id][1]}`).join(' ')

export function CyberBackdrop() {
  const reduced = useMemo(
    () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    [],
  )
  const radar = N.g

  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      {/* Atmosphere */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_70%_55%_at_50%_45%,rgb(79_140_255/0.10),transparent_70%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_40%_35%_at_85%_15%,rgb(139_92_246/0.08),transparent_70%)]" />
      <div className="netra-grid absolute inset-0 [mask-image:radial-gradient(ellipse_85%_75%_at_50%_50%,black_30%,transparent_85%)]" />

      <svg className="absolute inset-0 size-full" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice">
        <defs>
          {/* Keep the centre (behind the card) quiet */}
          <radialGradient id="cb-fade" cx="50%" cy="50%" r="50%">
            <stop offset="0.28" stopColor="black" />
            <stop offset="0.62" stopColor="white" />
          </radialGradient>
          <mask id="cb-mask" maskUnits="userSpaceOnUse" x="0" y="0" width="1600" height="1000">
            <rect width="1600" height="1000" fill="url(#cb-fade)" />
          </mask>
          <linearGradient id="cb-sweep" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="var(--primary)" stopOpacity="0" />
            <stop offset="1" stopColor="var(--primary)" stopOpacity="0.28" />
          </linearGradient>
        </defs>

        <g mask="url(#cb-mask)">
          {/* Radar */}
          <g className="hidden md:block">
            {[60, 120, 180].map((r) => (
              <circle key={r} cx={radar[0]} cy={radar[1]} r={r} fill="none" stroke="var(--primary)" strokeOpacity={0.1} strokeDasharray={r === 180 ? '2 6' : undefined} />
            ))}
            <line x1={radar[0] - 190} y1={radar[1]} x2={radar[0] + 190} y2={radar[1]} stroke="var(--primary)" strokeOpacity={0.06} />
            <line x1={radar[0]} y1={radar[1] - 190} x2={radar[0]} y2={radar[1] + 190} stroke="var(--primary)" strokeOpacity={0.06} />
            <g className="cb-spin" style={{ transformOrigin: `${radar[0]}px ${radar[1]}px` }}>
              <path d={`M${radar[0]},${radar[1]} L${radar[0] + 180},${radar[1]} A180,180 0 0 0 ${radar[0] + 127},${radar[1] - 127} Z`} fill="url(#cb-sweep)" />
              <line x1={radar[0]} y1={radar[1]} x2={radar[0] + 180} y2={radar[1]} stroke="var(--primary)" strokeOpacity={0.45} />
            </g>
          </g>

          {/* Network edges */}
          <g stroke="rgb(148 163 184)" strokeOpacity={0.14} strokeWidth={1}>
            {EDGES.map(([a, b]) => (
              <line key={`${a}${b}`} x1={N[a][0]} y1={N[a][1]} x2={N[b][0]} y2={N[b][1]} />
            ))}
          </g>

          {/* Occasionally illuminated paths */}
          {ROUTES.map((r, i) => (
            <path
              key={`glow-${i}`}
              d={path(r.via)}
              fill="none"
              stroke={r.tone === 'critical' ? 'var(--sev-critical)' : r.tone === 'violet' ? 'var(--brand-violet)' : 'var(--primary)'}
              strokeWidth={1.4}
              strokeLinecap="round"
              pathLength={1000}
              className={i > 3 ? 'cb-flow hidden md:block' : 'cb-flow'}
              style={{ animationDuration: `${r.dur}s`, animationDelay: `${r.begin}s` }}
            />
          ))}

          {/* Data particles along attack / data paths */}
          {!reduced &&
            ROUTES.map((r, i) =>
              [0, r.dur / 2].map((offset) => (
                <circle
                  key={`p-${i}-${offset}`}
                  r={r.tone === 'critical' ? 2.4 : 2}
                  fill={r.tone === 'critical' ? 'var(--sev-critical)' : r.tone === 'violet' ? 'var(--brand-violet)' : 'var(--tech-cyan)'}
                  className={i > 3 ? 'hidden md:block' : undefined}
                >
                  <animateMotion dur={`${r.dur}s`} begin={`${r.begin + offset}s`} repeatCount="indefinite" path={path(r.via)} rotate="auto" />
                  <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.08;0.92;1" dur={`${r.dur}s`} begin={`${r.begin + offset}s`} repeatCount="indefinite" />
                </circle>
              )),
            )}

          {/* Threat pulses */}
          {PULSES.map((p) => (
            <circle
              key={`pulse-${p.at}`}
              cx={N[p.at][0]}
              cy={N[p.at][1]}
              r={6}
              fill="none"
              stroke={p.color}
              strokeWidth={1.2}
              className="cb-pulse"
              style={{ animationDelay: `${p.delay}s` }}
            />
          ))}

          {/* Nodes */}
          {(Object.keys(N) as Id[]).map((id, i) => (
            <g key={id}>
              <circle cx={N[id][0]} cy={N[id][1]} r={5.5} fill="var(--background)" stroke="rgb(148 163 184)" strokeOpacity={0.35} />
              <circle
                cx={N[id][0]}
                cy={N[id][1]}
                r={2}
                fill={PULSES.find((p) => p.at === id)?.color ?? 'var(--primary)'}
                className="cb-node"
                style={{ animationDelay: `${(i % 7) * 0.7}s` }}
              />
            </g>
          ))}

          {/* Technical labels */}
          <g className="font-mono" fontSize={10} letterSpacing={1.5} fill="rgb(148 163 184)">
            {LABELS.map((l, i) => (
              <text
                key={l.text}
                x={N[l.at][0] + l.dx}
                y={N[l.at][1] + l.dy}
                className={l.dense ? 'cb-label hidden md:block' : 'cb-label'}
                style={{ animationDelay: `${i * 1.3}s` }}
              >
                {l.text}
              </text>
            ))}
          </g>

          {/* Transient security event indicators */}
          <g className="hidden font-mono md:block" fontSize={9.5} letterSpacing={1}>
            {ALERTS.map((a) => {
              const x = N[a.at][0] + a.dx
              const y = N[a.at][1] + a.dy
              return (
                <g key={a.text} className="cb-alert" style={{ animationDelay: `${a.delay}s` }}>
                  <rect x={x} y={y - 12} width={a.text.length * 6.6 + 22} height={18} rx={4} fill="rgb(9 12 17 / 0.8)" stroke={a.color} strokeOpacity={0.45} />
                  <circle cx={x + 9} cy={y - 3} r={2.5} fill={a.color} />
                  <text x={x + 17} y={y + 0.5} fill={a.color} fillOpacity={0.9}>
                    {a.text}
                  </text>
                </g>
              )
            })}
          </g>
        </g>

        {/* Encrypted data streams along top and bottom */}
        <g className="hidden md:block" stroke="var(--primary)" strokeOpacity={0.18} strokeWidth={1}>
          <line x1="0" y1="18" x2="1600" y2="18" strokeDasharray="2 10 18 10" className="cb-stream" />
          <line x1="0" y1="982" x2="1600" y2="982" strokeDasharray="2 10 18 10" className="cb-stream cb-stream-rev" />
        </g>
      </svg>

      {/* Vignette */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_75%_70%_at_50%_50%,transparent_55%,rgb(3_4_7/0.85)_100%)]" />
    </div>
  )
}
