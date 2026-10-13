import type * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { ArrowRight, RadioTower, ScanSearch } from 'lucide-react'
import { Link } from 'react-router-dom'
import { NetraMark } from '@/components/netra'
import { useAppTheme } from '@/layouts/useAppTheme'
import { CommandHomeBackdrop } from './home/CommandHomeBackdrop'
import { COMMAND_HOME, WORKSPACES, type WorkspaceId } from './home/content'

const ICONS: Record<WorkspaceId, LucideIcon> = {
  'live-tracking': RadioTower,
  'security-workspace': ScanSearch,
}

const ACCENTS: Record<WorkspaceId, string> = {
  'live-tracking': 'var(--tech-cyan)',
  'security-workspace': 'var(--brand-violet)',
}

const delay = (ms: number) => ({ '--ch-delay': `${ms}ms` }) as React.CSSProperties

/**
 * Signed-in home: pick a workspace. Navigation only — the cards link to existing
 * routes and change no session or permission state. Outside the app shell but on
 * its light theme (useAppTheme), like the briefing.
 */
export function CommandHomePage() {
  useAppTheme()
  return (
    <div className="relative isolate flex min-h-svh flex-col overflow-x-hidden bg-background text-foreground">
      <CommandHomeBackdrop />

      <main className="relative z-10 mx-auto flex w-full max-w-4xl flex-1 flex-col items-center justify-center px-4 py-14 text-center sm:px-6 sm:py-16 lg:px-8">
        <div className="ch-rise flex flex-col items-center">
          <NetraMark className="size-11 sm:size-12" />
          <p className="mt-4 pl-[0.34em] text-2xl font-semibold tracking-[0.34em] sm:text-[1.75rem]">NETRA</p>
          <p className="mt-2 flex items-center gap-3 font-mono text-[10px] tracking-[0.3em] text-primary uppercase sm:text-[11px]">
            <span aria-hidden className="hidden h-px w-8 bg-linear-to-r from-transparent to-cyan/50 sm:block" />
            {COMMAND_HOME.tagline}
            <span aria-hidden className="hidden h-px w-8 bg-linear-to-l from-transparent to-cyan/50 sm:block" />
          </p>
        </div>

        <h1 className="ch-rise mt-10 bg-linear-to-b from-foreground to-foreground/75 bg-clip-text text-[2rem] leading-tight font-semibold tracking-tight text-balance text-transparent sm:mt-12 sm:text-5xl" style={delay(100)}>
          {COMMAND_HOME.heading.lead}{' '}
          <span className="bg-linear-to-r from-primary to-violet bg-clip-text">{COMMAND_HOME.heading.accent}</span>
        </h1>
        <p className="ch-rise mt-4 max-w-md text-sm leading-relaxed text-muted-foreground sm:text-[15px]" style={delay(180)}>
          {COMMAND_HOME.description}
        </p>

        <nav aria-label="Workspaces" className="mt-10 w-full sm:mt-12">
          <ul className="grid grid-cols-1 gap-4 sm:grid-cols-2 sm:gap-5">
            {WORKSPACES.map((workspace, i) => {
              const Icon = ICONS[workspace.id]
              return (
                <li key={workspace.id} className="ch-rise" style={delay(260 + i * 90)}>
                  <Link
                    to={workspace.to}
                    className="ch-workspace group flex h-full items-center gap-4 rounded-2xl p-5 text-left sm:flex-col sm:items-start sm:gap-0 sm:p-7"
                    style={{ '--ch-accent': ACCENTS[workspace.id] } as React.CSSProperties}
                  >
                    <span aria-hidden className="ch-workspace-icon grid size-12 shrink-0 place-items-center rounded-xl sm:size-14">
                      <Icon className="size-5 sm:size-6" />
                    </span>
                    <span className="min-w-0 flex-1 sm:mt-6">
                      <span className="block text-lg font-semibold tracking-tight text-foreground sm:text-xl">{workspace.name}</span>
                      <span className="mt-1 block text-sm text-muted-foreground">{workspace.summary}</span>
                    </span>
                    <span aria-hidden className="ch-workspace-go grid size-9 shrink-0 place-items-center rounded-full sm:mt-8 sm:self-end">
                      <ArrowRight className="size-4 transition-transform duration-300 group-hover:translate-x-0.5 group-focus-visible:translate-x-0.5" />
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </nav>

        <figure className="ch-rise mt-12 flex max-w-lg flex-col items-center gap-4 sm:mt-14" style={delay(480)}>
          <span aria-hidden className="h-px w-16 bg-linear-to-r from-transparent via-primary/50 to-transparent" />
          <blockquote className="text-sm leading-relaxed text-foreground/75 italic sm:text-[15px]">
            <p>“{COMMAND_HOME.quote}”</p>
          </blockquote>
        </figure>
      </main>
    </div>
  )
}
