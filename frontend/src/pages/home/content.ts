/**
 * Command Home copy and workspace targets.
 *
 * Choosing a workspace is navigation only: each card links to an existing route and
 * changes no session or permission state. This module has no imports so `node --test`
 * can load it directly (tests/commandHome.test.ts).
 */

export const COMMAND_HOME = {
  tagline: 'Cyber Decision Intelligence',
  /** Rendered as one heading; the accent half gets the brand gradient. */
  heading: { lead: 'Your Security.', accent: 'One Command.' },
  description: 'Choose a workspace to watch activity as it arrives or investigate what it means.',
  quote: 'In cybersecurity, vigilance is the first line of defense.',
} as const

export type WorkspaceId = 'live-tracking' | 'security-workspace'

export interface Workspace {
  id: WorkspaceId
  name: string
  summary: string
  /** Must match an existing route in src/lib/navigation.ts (asserted by tests). */
  to: string
}

export const WORKSPACES = [
  { id: 'live-tracking', name: 'Live Tracking', summary: 'Monitor security activity.', to: '/collector' },
  { id: 'security-workspace', name: 'Security Workspace', summary: 'Investigate and assess threats.', to: '/dashboard' },
] as const satisfies readonly Workspace[]
