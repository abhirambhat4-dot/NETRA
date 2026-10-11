import type * as React from 'react'
import { LIFECYCLE } from '@/components/landing/content'

/**
 * Abstract evidence trail for the login page: unlabelled context nodes and the seven lifecycle
 * stages joined by one line that draws once. It shows no data — no scores, IDs, addresses,
 * products or alerts — and nothing loops. Login-only; the other auth pages keep CyberBackdrop.
 */

type Pt = readonly [number, number]

// One point per LIFECYCLE stage, in order; `label` offsets keep words clear of the trail.
const STAGES: { at: Pt; label: Pt; anchor: 'start' | 'end' }[] = [
  { at: [64, 74], label: [0, -18], anchor: 'start' },
  { at: [206, 118], label: [14, -12], anchor: 'start' },
  { at: [112, 200], label: [-14, 26], anchor: 'start' },
  { at: [266, 232], label: [0, 30], anchor: 'start' },
  { at: [404, 186], label: [12, -16], anchor: 'end' },
  { at: [330, 310], label: [-16, 28], anchor: 'start' },
  { at: [462, 360], label: [0, 30], anchor: 'end' },
]

const CONTEXT: Pt[] = [
  [28, 186], [168, 30], [330, 62], [486, 96], [38, 330], [196, 338], [238, 410], [504, 250], [414, 414],
]

// Context node index → stage index it connects to.
const CONTEXT_LINKS: [number, number][] = [
  [0, 2], [1, 1], [2, 1], [2, 4], [3, 4], [4, 2], [5, 3], [5, 5], [6, 5], [7, 4], [7, 6], [8, 6],
]

const TRAIL = STAGES.map(({ at }, i) => `${i ? 'L' : 'M'}${at[0]},${at[1]}`).join(' ')
const TRAIL_START = 500
const STAGE_GAP = 250

const delay = (ms: number) => ({ '--na-delay': `${ms}ms` }) as React.CSSProperties

export function LoginEvidenceTrail({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 540 440" className={className} aria-hidden focusable="false">
      <g className="na-fade" style={delay(150)}>
        {CONTEXT_LINKS.map(([c, s]) => (
          <line
            key={`${c}-${s}`}
            x1={CONTEXT[c][0]}
            y1={CONTEXT[c][1]}
            x2={STAGES[s].at[0]}
            y2={STAGES[s].at[1]}
            stroke="var(--nl-line-strong)"
            strokeWidth={1}
            strokeDasharray="3 5"
          />
        ))}
        {CONTEXT.map(([x, y]) => (
          <circle key={`${x}-${y}`} cx={x} cy={y} r={4} fill="#FFFFFF" stroke="var(--nl-line-strong)" strokeWidth={1.25} />
        ))}
      </g>

      <path
        d={TRAIL}
        pathLength={1}
        className="na-draw"
        style={delay(TRAIL_START)}
        fill="none"
        stroke="var(--primary)"
        strokeOpacity={0.55}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {STAGES.map(({ at, label, anchor }, i) => {
        const d = delay(TRAIL_START + i * STAGE_GAP)
        return (
          <g key={LIFECYCLE[i].key}>
            <g className="na-node" style={d}>
              <circle cx={at[0]} cy={at[1]} r={9} fill="#FFFFFF" stroke="var(--primary)" strokeWidth={2} />
              <circle cx={at[0]} cy={at[1]} r={3} fill="var(--primary)" />
            </g>
            <text
              x={at[0] + label[0]}
              y={at[1] + label[1]}
              textAnchor={anchor}
              className="na-fade"
              style={d}
              fill="var(--foreground)"
              fontSize={13}
              fontWeight={600}
            >
              {LIFECYCLE[i].label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
