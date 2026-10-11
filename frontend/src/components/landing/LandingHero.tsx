import type * as React from 'react'
import { ArrowRight, Check } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { HERO, LANDING_LINKS, SECTION_IDS } from './content'
import { EvidencePreview } from './EvidencePreview'

const delay = (ms: number) => ({ '--nl-delay': `${ms}ms` }) as React.CSSProperties

export function LandingHero() {
  return (
    <section aria-labelledby="hero-title" className="relative isolate overflow-hidden">
      <div aria-hidden className="nl-hero-backdrop absolute inset-0 -z-10" />
      <div aria-hidden className="nl-hero-grid absolute inset-0 -z-10" />

      <div className="mx-auto grid max-w-300 items-center gap-14 px-4 pt-14 pb-20 sm:px-6 sm:pt-20 lg:grid-cols-[1.05fr_0.95fr] lg:gap-16 lg:px-8 lg:pt-24 lg:pb-28">
        <div className="min-w-0">
          <p
            className="nl-rise inline-flex max-w-full items-center gap-2 rounded-full border border-primary/15 bg-(--nl-accent-soft) px-3 py-1.5 text-sm font-medium text-primary"
            style={delay(0)}
          >
            <span aria-hidden className="size-1.5 shrink-0 rounded-full bg-primary" />
            {HERO.eyebrow}
          </p>

          <h1
            id="hero-title"
            className="nl-rise mt-6 max-w-xl text-4xl leading-[1.08] font-semibold tracking-tight text-balance text-foreground sm:text-5xl lg:text-[3.5rem]"
            style={delay(90)}
          >
            {HERO.title}
          </h1>

          <p className="nl-rise mt-6 max-w-xl text-lg leading-relaxed text-pretty text-muted-foreground" style={delay(180)}>
            {HERO.description}
          </p>

          <div className="nl-rise mt-9 flex flex-col gap-3 sm:flex-row" style={delay(270)}>
            <Button asChild className="h-12 rounded-full px-6 text-[15px] font-semibold shadow-sm hover:bg-[#1E40AF]">
              <Link to={LANDING_LINKS.signIn}>
                {HERO.primaryCta}
                <ArrowRight className="nl-arrow size-4" aria-hidden />
              </Link>
            </Button>
            <Button
              asChild
              variant="secondary"
              className="h-12 rounded-full border-(--nl-line-strong) px-6 text-[15px] font-semibold shadow-sm hover:border-primary/40 hover:bg-(--nl-accent-soft)"
            >
              <a href={`#${SECTION_IDS.lifecycle}`}>{HERO.secondaryCta}</a>
            </Button>
          </div>

          <ul className="nl-rise mt-10 grid gap-2.5 text-sm text-muted-foreground" style={delay(360)}>
            {HERO.highlights.map((item) => (
              <li key={item} className="flex items-start gap-2.5">
                <span aria-hidden className="mt-0.5 grid size-4.5 shrink-0 place-items-center rounded-full bg-(--nl-accent-soft) text-primary">
                  <Check className="size-3" />
                </span>
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="nl-rise min-w-0" style={delay(320)}>
          <EvidencePreview />
        </div>
      </div>
    </section>
  )
}
