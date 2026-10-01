import { ArrowRight, Sparkles } from 'lucide-react'
import { Link } from 'react-router-dom'
import { NetraLogo } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'
import { SignalNetwork } from './SignalNetwork'

export function LandingHero() {
  return (
    <section className="relative overflow-hidden rounded-[32px] border border-border/80 bg-[radial-gradient(ellipse_at_top,rgba(56,217,255,0.12),transparent_42%),linear-gradient(180deg,rgba(10,15,22,0.94),rgba(8,12,18,0.95))] px-4 py-8 sm:px-6 lg:px-8 lg:py-12">
      <div className="absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,rgba(56,217,255,0.9),transparent)]" />

      <header className="relative z-10 flex items-center justify-between">
        <NetraLogo className="h-8 w-auto" />
        <Button asChild variant="ghost" size="sm" className="rounded-full border border-border/80 bg-background/30 text-muted-foreground hover:text-foreground">
          <Link to={ROUTES.login}>Sign in</Link>
        </Button>
      </header>

      <div className="relative z-10 mt-10 grid items-center gap-10 lg:grid-cols-[1.05fr_0.95fr]">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/8 px-3 py-1 text-[10px] font-medium tracking-[0.22em] text-primary uppercase">
            <Sparkles className="size-3.5" />
            CYBER DECISION INTELLIGENCE
          </div>

          <h1 className="mt-6 max-w-xl text-5xl font-semibold tracking-[-0.08em] text-foreground sm:text-6xl lg:text-[5rem] lg:leading-[0.92]">
            SEE THE SIGNAL.
            <span className="mt-2 block text-primary/95">UNDERSTAND THE RISK.</span>
            <span className="mt-2 block text-white/90">CONTROL THE RESPONSE.</span>
          </h1>

          <p className="mt-6 max-w-xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            NETRA takes security events, adds context, correlates evidence, calculates explainable risk,
            prioritizes the incident, recommends action, and helps teams respond with authorization, control,
            and learning from outcomes.
          </p>

          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Button asChild size="lg" className="h-12 rounded-full px-6 text-[11px] font-semibold tracking-[0.16em] uppercase">
              <a href="#what-netra-is">
                Explore NETRA
                <ArrowRight className="ml-2 size-4" />
              </a>
            </Button>
            <Button asChild variant="outline" size="lg" className="h-12 rounded-full border-border bg-background/30 px-6 text-[11px] font-semibold tracking-[0.16em] uppercase text-foreground">
              <Link to={ROUTES.login}>Enter Platform</Link>
            </Button>
          </div>

          <div className="mt-10 flex flex-wrap items-center gap-3 text-[10px] font-medium tracking-[0.18em] text-muted-foreground uppercase">
            <span className="rounded-full border border-border bg-background/30 px-2.5 py-1.5">Event correlation</span>
            <span className="rounded-full border border-border bg-background/30 px-2.5 py-1.5">Context-aware risk</span>
            <span className="rounded-full border border-border bg-background/30 px-2.5 py-1.5">Controlled response</span>
          </div>
        </div>

        <div className="relative">
          <SignalNetwork />
        </div>
      </div>
    </section>
  )
}
