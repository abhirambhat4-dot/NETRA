const NODES = [
  { x: 10, y: 28, size: 6, tone: 'primary' },
  { x: 24, y: 52, size: 5, tone: 'cyan' },
  { x: 36, y: 22, size: 6, tone: 'violet' },
  { x: 50, y: 62, size: 7, tone: 'primary' },
  { x: 64, y: 38, size: 6, tone: 'violet' },
  { x: 78, y: 66, size: 5, tone: 'cyan' },
  { x: 90, y: 28, size: 6, tone: 'primary' },
  { x: 68, y: 18, size: 5, tone: 'warning' },
  { x: 14, y: 76, size: 6, tone: 'critical' },
  { x: 92, y: 84, size: 6, tone: 'primary' },
  { x: 54, y: 28, size: 5, tone: 'cyan' },
  { x: 42, y: 80, size: 5, tone: 'critical' },
] as const

const EDGES = [
  [0, 1], [1, 3], [3, 4], [4, 5], [5, 9], [2, 4], [2, 10], [10, 3], [10, 0], [1, 6], [6, 7], [7, 4], [8, 11], [11, 3], [11, 9],
] as const

const toneMap = {
  primary: '#38D9FF',
  cyan: '#7DD3FC',
  violet: '#4F7CFF',
  warning: '#F5B942',
  critical: '#FF4D5E',
} as const

export function SignalNetwork() {
  return (
    <div className="relative h-[360px] w-full overflow-hidden rounded-[30px] border border-border/80 bg-[radial-gradient(circle_at_50%_30%,rgba(56,217,255,0.15),transparent_40%),linear-gradient(180deg,rgba(12,18,26,0.94),rgba(8,11,16,0.9))] p-3 shadow-[0_30px_80px_-40px_rgba(79,124,255,0.55)]">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] [background-size:30px_30px]" />
      <svg viewBox="0 0 100 100" className="relative z-10 h-full w-full" aria-hidden="true">
        <defs>
          <linearGradient id="netra-signal" x1="0" x2="1" y1="0" y2="1">
            <stop offset="0%" stopColor="#38D9FF" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#4F7CFF" stopOpacity="0.3" />
          </linearGradient>
        </defs>

        {EDGES.map(([from, to], index) => {
          const a = NODES[from]
          const b = NODES[to]

          return (
            <line
              key={`${from}-${to}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="url(#netra-signal)"
              strokeOpacity="0.55"
              strokeWidth="0.75"
              strokeDasharray={index % 4 === 0 ? '2 4' : undefined}
            />
          )
        })}

        {NODES.map((node, index) => (
          <g key={`${node.x}-${node.y}`}>
            <circle cx={node.x} cy={node.y} r={node.size + 1.4} fill={toneMap[node.tone]} opacity="0.12" />
            <circle cx={node.x} cy={node.y} r={node.size} fill={toneMap[node.tone]} opacity="0.9" />
            <circle cx={node.x} cy={node.y} r={1.2} fill="#F8FAFC" opacity="0.9" style={{ animationDelay: `${index * 0.25}s` }} className="animate-[pulse_3s_ease-in-out_infinite]" />
          </g>
        ))}

        <path d="M 10 86 Q 28 74 50 80 T 92 72" fill="none" stroke="#38D9FF" strokeOpacity="0.5" strokeWidth="0.8" strokeDasharray="1.5 3" />
      </svg>
    </div>
  )
}
