import type * as React from 'react'
import { useRef } from 'react'
import type { LucideIcon } from 'lucide-react'
import { ArrowRight, Ban, BookOpen, FlaskConical, Info, Layers, Link2, RadioTower, Route, Scale, SearchX, UserCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import { LandingHero } from '@/components/landing/LandingHero'
import { LandingNav } from '@/components/landing/LandingNav'
import { LandingFooter } from '@/components/landing/LandingFooter'
import { LifecycleFlow } from '@/components/landing/LifecycleFlow'
import { FeatureCard } from '@/components/landing/FeatureCard'
import { SectionHeader } from '@/components/landing/SectionHeader'
import { StatusChip } from '@/components/landing/StatusChip'
import { useReveal } from '@/components/landing/useReveal'
import {
  CLOSING_CTA,
  FEATURES,
  LANDING_LINKS,
  NON_CLAIMS,
  PRINCIPLES,
  PRIORITISATION,
  PROBLEMS,
  RISK_FACTORS,
  SECTION_IDS,
  STATUS_META,
  type FeatureStatus,
} from '@/components/landing/content'

const PROBLEM_ICONS: LucideIcon[] = [Layers, Scale, Route]
const PRINCIPLE_ICONS: LucideIcon[] = [Link2, UserCheck, FlaskConical, BookOpen, Info, RadioTower]

const CONTAINER = 'mx-auto max-w-300 px-4 sm:px-6 lg:px-8'
const SECTION = 'py-20 sm:py-24'

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

        {/* The problem */}
        <section id={SECTION_IDS.problem} aria-labelledby="problem-title" className={`nl-band ${SECTION}`}>
          <div className={CONTAINER}>
            <SectionHeader
              titleId="problem-title"
              eyebrow="The problem"
              title="Security data alone does not tell you what to do next."
              description="Given the security records and context that are actually available, what should be investigated first, why, and what is a sensible next step?"
            />
            <ul className="mt-12 grid gap-5 md:grid-cols-3">
              {PROBLEMS.map((problem, i) => {
                const Icon = PROBLEM_ICONS[i]
                return (
                  <li key={problem.title} data-reveal style={delay(i * 100)}>
                    <div className="nl-card h-full rounded-3xl border border-(--nl-line) bg-white p-6 shadow-[0_1px_2px_rgba(11,27,51,0.04)]">
                      <span aria-hidden className="grid size-11 place-items-center rounded-2xl bg-(--nl-accent-soft) text-primary">
                        <Icon className="size-5" />
                      </span>
                      <h3 className="mt-5 text-lg font-semibold text-foreground">{problem.title}</h3>
                      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{problem.text}</p>
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
        </section>

        {/* Lifecycle */}
        <section id={SECTION_IDS.lifecycle} aria-labelledby="lifecycle-title" className={SECTION}>
          <div className={CONTAINER}>
            <SectionHeader
              titleId="lifecycle-title"
              eyebrow="How NETRA works"
              title="Seven stages from candidate activity to recorded lesson."
              description="Each stage builds on evidence from the one before it, and a person stays in control before any response is carried out."
              align="center"
            />
            <div className="mt-14">
              <LifecycleFlow />
            </div>
          </div>
        </section>

        {/* Capabilities */}
        <section id={SECTION_IDS.capabilities} aria-labelledby="capabilities-title" className={`nl-band ${SECTION}`}>
          <div className={CONTAINER}>
            <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
              <SectionHeader
                titleId="capabilities-title"
                eyebrow="Capabilities"
                title="Seven feature areas, each with an honest status."
                description="Every card states what is implemented today and where its boundary lies."
              />
              <dl data-reveal className="grid gap-3 rounded-3xl border border-(--nl-line) bg-white p-5 text-sm lg:max-w-sm">
                {(Object.keys(STATUS_META) as FeatureStatus[]).map((status) => (
                  <div key={status} className="grid gap-1.5 sm:grid-cols-[auto_1fr] sm:items-center sm:gap-3">
                    <dt>
                      <StatusChip status={status} />
                    </dt>
                    <dd className="text-muted-foreground">{STATUS_META[status].description}</dd>
                  </div>
                ))}
              </dl>
            </div>

            <ul className="mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
              {FEATURES.map((feature, i) => {
                const wide = i === FEATURES.length - 1
                return (
                  <li
                    key={feature.id}
                    data-reveal
                    style={delay((i % 3) * 100)}
                    className={wide ? 'md:col-span-2 lg:col-span-3' : undefined}
                  >
                    <FeatureCard feature={feature} wide={wide} />
                  </li>
                )
              })}
            </ul>
          </div>
        </section>

        {/* Explainable prioritisation */}
        <section id={SECTION_IDS.prioritisation} aria-labelledby="prioritisation-title" className={SECTION}>
          <div className={`${CONTAINER} grid gap-12 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16`}>
            <div>
              <SectionHeader
                titleId="prioritisation-title"
                eyebrow={PRIORITISATION.eyebrow}
                title={PRIORITISATION.title}
                description={PRIORITISATION.description}
              />
              <div data-reveal style={delay(120)} className="mt-8 rounded-3xl border border-[#FDE68A] bg-[#FFFBEB] p-5">
                <p className="flex items-center gap-2 text-sm font-semibold text-[#92400E]">
                  <SearchX className="size-4" aria-hidden />
                  {PRIORITISATION.missingTitle}
                </p>
                <p className="mt-2 text-sm leading-relaxed text-[#78350F]">{PRIORITISATION.missingText}</p>
              </div>
            </div>

            <div data-reveal style={delay(80)} className="nl-surface rounded-3xl p-2 sm:p-3">
              <h3 className="px-4 pt-4 pb-2 text-sm font-semibold text-foreground">Documented risk factors</h3>
              <ul className="divide-y divide-(--nl-line)">
                {RISK_FACTORS.map((factor) => (
                  <li key={factor.key} className="flex gap-4 rounded-2xl px-4 py-4 transition-colors hover:bg-(--nl-band)">
                    <span aria-hidden className="mt-1.5 size-2 shrink-0 rounded-full bg-primary" />
                    <div className="min-w-0">
                      <p className="font-semibold text-foreground">{factor.label}</p>
                      <p className="mt-0.5 text-sm leading-relaxed text-muted-foreground">{factor.text}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* Controls, evidence and scope */}
        <section id={SECTION_IDS.scope} aria-labelledby="scope-title" className={`nl-band ${SECTION}`}>
          <div className={CONTAINER}>
            <SectionHeader
              titleId="scope-title"
              eyebrow="Controls and scope"
              title="Clear about what NETRA does, and what it does not claim."
              description="NETRA's value depends on every displayed result being supported by data and implemented logic."
            />

            <ul className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {PRINCIPLES.map((principle, i) => {
                const Icon = PRINCIPLE_ICONS[i]
                return (
                  <li key={principle.title} data-reveal style={delay((i % 3) * 100)}>
                    <div className="nl-card flex h-full gap-4 rounded-3xl border border-(--nl-line) bg-white p-5 shadow-[0_1px_2px_rgba(11,27,51,0.04)]">
                      <span aria-hidden className="grid size-10 shrink-0 place-items-center rounded-xl bg-(--nl-accent-soft) text-primary">
                        <Icon className="size-4.5" />
                      </span>
                      <div className="min-w-0">
                        <h3 className="font-semibold text-foreground">{principle.title}</h3>
                        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{principle.text}</p>
                      </div>
                    </div>
                  </li>
                )
              })}
            </ul>

            <div data-reveal className="mt-8 rounded-3xl border border-(--nl-line) bg-white p-6 sm:p-8">
              <h3 id="non-claims-title" className="text-xl font-semibold text-foreground">
                What NETRA does not claim
              </h3>
              <p className="mt-2 text-sm text-muted-foreground">
                These are outside the current scope unless they are separately implemented and verified.
              </p>
              <ul aria-labelledby="non-claims-title" className="mt-6 grid gap-x-10 gap-y-4 md:grid-cols-2">
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
