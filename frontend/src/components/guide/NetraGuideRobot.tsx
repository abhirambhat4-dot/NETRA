import { useId } from 'react'
import type { GuideTone } from '@/lib/guide'
import { cn } from '@/lib/utils'

export type RobotState = 'idle' | 'guiding' | 'speaking'

interface NetraGuideRobotProps {
  tone?: GuideTone
  state?: RobotState
  className?: string
}

/**
 * NETRA's security-analysis drone: an angular hovering shell with an
 * illuminated visor, side sensor pods and a small stabiliser thruster.
 * Pure SVG — colour follows `--ng-accent` (tone), motion is CSS (ng-* classes
 * in index.css) and switches off under prefers-reduced-motion.
 */
export function NetraGuideRobot({ tone = 'normal', state = 'idle', className }: NetraGuideRobotProps) {
  const id = useId()
  const shell = `${id}-shell`
  const visor = `${id}-visor`

  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden
      data-tone={tone}
      data-state={state}
      className={cn('ng-robot', className)}
    >
      <defs>
        <linearGradient id={shell} x1="12" y1="6" x2="36" y2="36" gradientUnits="userSpaceOnUse">
          <stop stopColor="#1a2436" />
          <stop offset="1" stopColor="#070b12" />
        </linearGradient>
        <linearGradient id={visor} x1="13" y1="17" x2="35" y2="24" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--ng-accent)" stopOpacity="0.3" />
          <stop offset="0.5" stopColor="var(--ng-accent)" stopOpacity="0.12" />
          <stop offset="1" stopColor="var(--ng-accent)" stopOpacity="0.3" />
        </linearGradient>
      </defs>

      {/* Stabiliser glow — stays on the "ground" while the body floats */}
      <ellipse className="ng-shadow" cx="24" cy="43.5" rx="7" ry="1.4" fill="var(--ng-accent)" opacity="0.28" />

      <g className="ng-body">
        {/* Sensor mast */}
        <path d="M22 8.2 24 5.2l2 3" stroke="rgb(148 163 184 / 0.55)" strokeWidth="1" strokeLinejoin="round" />
        <circle className="ng-sensor" cx="24" cy="4.6" r="1.1" fill="var(--ng-accent)" />

        {/* Side sensor pods */}
        <path d="M10 17.5 6.6 18.6v5.8l3.4 1.1Z" fill="#0c1320" stroke="rgb(148 163 184 / 0.35)" strokeWidth="0.8" strokeLinejoin="round" />
        <path d="m38 17.5 3.4 1.1v5.8L38 25.5Z" fill="#0c1320" stroke="rgb(148 163 184 / 0.35)" strokeWidth="0.8" strokeLinejoin="round" />
        <circle className="ng-sensor ng-sensor-b" cx="8.3" cy="21.5" r="0.8" fill="var(--ng-accent)" />
        <circle className="ng-sensor ng-sensor-c" cx="39.7" cy="21.5" r="0.8" fill="var(--ng-accent)" />

        {/* Shell */}
        <path
          d="M16 8.5h16l6 6v13l-6 6H16l-6-6v-13Z"
          fill={`url(#${shell})`}
          stroke="rgb(148 163 184 / 0.42)"
          strokeWidth="0.9"
          strokeLinejoin="round"
        />
        {/* Panel seams */}
        <path d="M16 8.5 18.5 13h11L32 8.5M10 27.5h4l2 6M38 27.5h-4l-2 6" stroke="rgb(148 163 184 / 0.16)" strokeWidth="0.7" />

        {/* Visor */}
        <path d="M13.5 16.5h21l-2 8h-17Z" fill="#03101a" stroke="var(--ng-accent)" strokeOpacity="0.75" strokeWidth="0.9" strokeLinejoin="round" />
        <path className="ng-visor" d="M13.5 16.5h21l-2 8h-17Z" fill={`url(#${visor})`} />
        {/* Sensor line across the visor, with a brighter scanning segment */}
        <rect x="16.5" y="19.9" width="15" height="1.2" rx="0.6" fill="var(--ng-accent)" opacity="0.35" />
        <rect className="ng-scan" x="21.5" y="19.5" width="5" height="2" rx="1" fill="var(--ng-accent)" />

        {/* Light strips on the lower bevels */}
        <path className="ng-strip" d="m12.6 28.4 2.6 2.6M35.4 28.4l-2.6 2.6" stroke="var(--ng-accent)" strokeWidth="0.9" strokeLinecap="round" opacity="0.6" />

        {/* Thruster */}
        <path d="M20.5 33.5h7l-1.4 2.6h-4.2Z" fill="#0c1320" stroke="rgb(148 163 184 / 0.35)" strokeWidth="0.7" strokeLinejoin="round" />
        <path className="ng-thrust" d="M22.2 36.4h3.6l-1.8 2.6Z" fill="var(--ng-accent)" opacity="0.55" />
      </g>
    </svg>
  )
}
