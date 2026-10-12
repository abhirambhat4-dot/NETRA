import { useEffect, useRef, useState } from 'react'
import { Menu, X } from 'lucide-react'
import { Link } from 'react-router-dom'
import { NetraLogo, NetraMark } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'
import { LANDING_LINKS, NAV_ANCHORS } from './content'

const MENU_ID = 'landing-mobile-menu'

export function LandingNav() {
  const [scrolled, setScrolled] = useState(false)
  const [open, setOpen] = useState(false)
  const toggleRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      setOpen(false)
      toggleRef.current?.focus()
    }
    // Close if the viewport grows past the breakpoint where the menu is hidden.
    const wide = window.matchMedia('(min-width: 48rem)')
    const onWide = () => wide.matches && setOpen(false)
    document.addEventListener('keydown', onKey)
    wide.addEventListener('change', onWide)
    return () => {
      document.removeEventListener('keydown', onKey)
      wide.removeEventListener('change', onWide)
    }
  }, [open])

  return (
    <header
      data-scrolled={scrolled || open}
      className="nl-header sticky top-0 z-40 border-b border-transparent bg-white/80 backdrop-blur-md"
    >
      <div className="mx-auto flex h-16 max-w-300 items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <Link
          to={ROUTES.home}
          onClick={() => window.scrollTo({ top: 0 })}
          aria-label="NETRA home"
          className="-m-1 rounded-lg p-1 text-foreground outline-none focus-visible:ring-3 focus-visible:ring-ring"
        >
          <NetraLogo className="hidden sm:flex" />
          <span className="flex items-center gap-2.5 sm:hidden">
            <NetraMark />
            <span className="text-[15px] font-semibold tracking-[0.2em]">NETRA</span>
          </span>
        </Link>

        <nav aria-label="Page sections" className="hidden md:block">
          <ul className="flex items-center gap-1">
            {NAV_ANCHORS.map((a) => (
              <li key={a.id}>
                <a
                  href={`#${a.id}`}
                  className="nl-nav-link block rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-colors outline-none hover:text-foreground focus-visible:text-foreground focus-visible:ring-3 focus-visible:ring-ring"
                >
                  {a.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div className="flex items-center gap-2">
          <Link
            to={LANDING_LINKS.register}
            className="hidden h-10 items-center rounded-full px-4 text-sm font-medium text-foreground transition-colors outline-none hover:bg-(--nl-accent-soft) focus-visible:ring-3 focus-visible:ring-ring md:inline-flex"
          >
            Create account
          </Link>
          <Button asChild className="h-10 rounded-full px-5 text-sm font-semibold shadow-sm hover:bg-[#1E40AF]">
            <Link to={LANDING_LINKS.signIn}>Sign in</Link>
          </Button>
          <button
            ref={toggleRef}
            type="button"
            aria-expanded={open}
            aria-controls={MENU_ID}
            aria-label={open ? 'Close menu' : 'Open menu'}
            onClick={() => setOpen((v) => !v)}
            className="grid size-10 place-items-center rounded-full border border-(--nl-line) text-foreground transition-colors outline-none hover:bg-(--nl-accent-soft) focus-visible:ring-3 focus-visible:ring-ring md:hidden"
          >
            {open ? <X className="size-5" aria-hidden /> : <Menu className="size-5" aria-hidden />}
          </button>
        </div>
      </div>

      {open && (
        <div id={MENU_ID} className="nl-menu border-t border-(--nl-line) bg-white md:hidden">
          <nav aria-label="Page sections" className="mx-auto max-w-300 px-4 py-3 sm:px-6">
            <ul className="grid gap-1">
              {NAV_ANCHORS.map((a) => (
                <li key={a.id}>
                  <a
                    href={`#${a.id}`}
                    onClick={() => setOpen(false)}
                    className="flex min-h-11 items-center rounded-lg px-3 text-base font-medium text-foreground outline-none hover:bg-(--nl-accent-soft) focus-visible:ring-3 focus-visible:ring-ring"
                  >
                    {a.label}
                  </a>
                </li>
              ))}
              <li className="mt-1 border-t border-(--nl-line) pt-2">
                <Link
                  to={LANDING_LINKS.register}
                  className="flex min-h-11 items-center rounded-lg px-3 text-base font-medium text-primary outline-none hover:bg-(--nl-accent-soft) focus-visible:ring-3 focus-visible:ring-ring"
                >
                  Create account
                </Link>
              </li>
            </ul>
          </nav>
        </div>
      )}
    </header>
  )
}
