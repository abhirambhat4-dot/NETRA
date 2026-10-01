import type * as React from 'react'
import { LockKeyhole } from 'lucide-react'
import { NetraGuide } from '@/components/guide'
import { NetraLogo } from '@/components/netra'
import { CyberBackdrop } from './CyberBackdrop'

/** Card shell shared by the password recovery pages; mirrors the registration card. */
export function AuthCard({ titleId, title, description, children }: {
  titleId: string
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <div className="relative isolate flex min-h-svh flex-col overflow-hidden bg-background">
      <CyberBackdrop />
      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-10 sm:px-6">
        <div className="relative w-full max-w-[420px]">
          <div aria-hidden className="absolute -inset-6 -z-10 rounded-[2rem] bg-[radial-gradient(ellipse_at_top,rgb(79_140_255/0.22),transparent_65%),radial-gradient(ellipse_at_bottom,rgb(139_92_246/0.14),transparent_60%)] blur-2xl" />
          <section aria-labelledby={titleId} className="relative overflow-hidden rounded-2xl border border-white/10 bg-[linear-gradient(180deg,rgb(21_26_35/0.82),rgb(10_13_19/0.86))] shadow-[inset_0_1px_0_rgb(255_255_255/0.06),0_1px_2px_rgb(0_0_0/0.5),0_24px_60px_-20px_rgb(0_0_0/0.85),0_0_0_1px_rgb(79_140_255/0.06)] backdrop-blur-xl">
            <span aria-hidden className="absolute inset-x-10 top-0 h-px bg-linear-to-r from-transparent via-primary/70 to-transparent" />
            <div className="px-7 pt-7 pb-6 sm:px-8">
              <NetraLogo />
              <div className="mt-7 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/8 px-2.5 py-1 text-[10px] font-semibold tracking-[0.18em] text-primary uppercase">
                <LockKeyhole className="size-3" /> Secure command access
              </div>
              <h1 id={titleId} className="mt-3 text-[1.625rem] leading-tight font-semibold tracking-tight">{title}</h1>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{description}</p>
              {children}
            </div>
          </section>
        </div>
      </main>
      <NetraGuide page="login" />
    </div>
  )
}
