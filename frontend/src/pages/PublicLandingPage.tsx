import type * as React from 'react'
import { useRef } from 'react'
import { ArrowRight, Ban } from 'lucide-react'
import { Link } from 'react-router-dom'
import { LandingHero } from '@/components/landing/LandingHero'
import { LandingNav } from '@/components/landing/LandingNav'
import { LandingFooter } from '@/components/landing/LandingFooter'
import { LifecycleFlow } from '@/components/landing/LifecycleFlow'
import { FeatureCard } from '@/components/landing/FeatureCard'
import { SectionHeader } from '@/components/landing/SectionHeader'
import { useReveal } from '@/components/landing/useReveal'
import { CLOSING_CTA, FEATURES, LANDING_LINKS, NON_CLAIMS, SECTION_IDS } from '@/components/landing/content'

const CONTAINER = 'mx-auto max-w-300 px-4 sm:px-6 lg:px-8'
const SECTION = 'py-16 sm:py-20'

const delay = (ms: number) => ({ '--nl-delay': `${ms}ms` }) as React.CSSProperties

export function PublicLandingPage() {
  const rootRef = useRef<HTMLDivElement>(null)
  useReveal(rootRef)

  return (
    <div ref={rootRef} className="netra-landing relative isolate font-sans">
      <a
        href={`#${SECTION_IDS.main}`}
        className="sr-only rounded-full bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground shadow-lg focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:outline-none focus-visible:ring-3 focus-visible:ring-ring"
      >
        Skip to main content
      </a>

      <LandingNav />

      <main id={SECTION_IDS.main} tabIndex={-1} className="outline-none">
        <LandingHero />

        {/* Workflow */}
        <section id={SECTION_IDS.lifecycle} aria-labelledby="lifecycle-title" className={`nl-band ${SECTION}`}>
          <div className={CONTAINER}>
            <SectionHeader
              titleId="lifecycle-title"
              eyebrow="How NETRA works"
              title="Six steps, with a person in control."
              description="Monitor → Detect → Assess → Authorize → Respond → Learn"
              align="center"
            />
            <div className="mt-12">
              <LifecycleFlow />
            </div>
          </div>
        </section>

        {/* Capabilities */}
        <section id={SECTION_IDS.capabilities} aria-labelledby="capabilities-title" className={SECTION}>
          <div className={CONTAINER}>
            <SectionHeader
              titleId="capabilities-title"
              eyebrow="Capabilities"
              title="What NETRA does today."
              description="Each card states its status and where its boundary lies."
            />

            <ul className="mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
              {FEATURES.map((feature, i) => (
                <li key={feature.id} data-reveal style={delay((i % 3) * 100)}>
                  <FeatureCard feature={feature} />
                </li>
              ))}
            </ul>

            <div id={SECTION_IDS.scope} data-reveal className="mt-8 scroll-mt-20 rounded-3xl border border-(--nl-line) bg-white p-6 sm:p-8">
              <h3 id="non-claims-title" className="text-xl font-semibold text-foreground">
                What NETRA does not claim
              </h3>
              <ul aria-labelledby="non-claims-title" className="mt-5 grid gap-x-10 gap-y-3 md:grid-cols-2">
                {NON_CLAIMS.map((item) => (
                  <li key={item} className="flex items-start gap-3 text-sm leading-relaxed text-foreground">
                    <Ban className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* Closing call to action */}
        <section aria-labelledby="closing-title" className={SECTION}>
          <div className={CONTAINER}>
            <div
              data-reveal
              className="relative overflow-hidden rounded-[2rem] bg-(--nl-navy) px-6 py-12 text-white sm:px-12 sm:py-16"
            >
              <div
                aria-hidden
                className="absolute inset-0 bg-[radial-gradient(ellipse_60%_80%_at_100%_0%,rgba(59,130,246,0.22),transparent_70%)]"
              />
              <div className="relative flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
                <div className="max-w-xl">
                  <h2 id="closing-title" className="text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
                    {CLOSING_CTA.title}
                  </h2>
                  <p className="mt-4 text-lg leading-relaxed text-[#CBD5E1]">{CLOSING_CTA.description}</p>
                </div>
                <div className="flex flex-col gap-3 sm:flex-row">
                  <Link
                    to={LANDING_LINKS.signIn}
                    className="inline-flex h-12 items-center justify-center gap-2 rounded-full bg-white px-6 text-[15px] font-semibold text-(--nl-navy) shadow-sm transition-colors outline-none hover:bg-[#E0E7FF] focus-visible:ring-3 focus-visible:ring-white/70"
                  >
                    Sign in
                    <ArrowRight className="nl-arrow size-4" aria-hidden />
                  </Link>
                  <Link
                    to={LANDING_LINKS.register}
                    className="inline-flex h-12 items-center justify-center rounded-full border border-white/35 px-6 text-[15px] font-semibold text-white transition-colors outline-none hover:border-white/70 hover:bg-white/10 focus-visible:ring-3 focus-visible:ring-white/70"
                  >
                    Create account
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <LandingFooter />
    </div>
  )
}
