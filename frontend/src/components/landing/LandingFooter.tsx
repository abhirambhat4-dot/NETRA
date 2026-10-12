import { Link } from 'react-router-dom'
import { NetraLogo } from '@/components/netra'
import { LANDING_LINKS, LANDING_TAGLINE, NAV_ANCHORS } from './content'

const LINK = 'rounded-md text-sm text-muted-foreground transition-colors outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring'

export function LandingFooter() {
  return (
    <footer className="border-t border-(--nl-line) bg-white">
      <div className="mx-auto flex max-w-300 flex-col gap-8 px-4 py-12 sm:px-6 md:flex-row md:items-start md:justify-between lg:px-8">
        <div className="max-w-sm">
          <NetraLogo />
          <p className="mt-4 text-sm leading-relaxed text-muted-foreground">{LANDING_TAGLINE}.</p>
        </div>

        <div className="grid grid-cols-2 gap-10 sm:gap-16">
          <nav aria-label="Footer: page sections">
            <p className="text-sm font-semibold text-foreground">On this page</p>
            <ul className="mt-3 grid gap-2.5">
              {NAV_ANCHORS.map((a) => (
                <li key={a.id}>
                  <a href={`#${a.id}`} className={LINK}>
                    {a.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <nav aria-label="Footer: account">
            <p className="text-sm font-semibold text-foreground">Account</p>
            <ul className="mt-3 grid gap-2.5">
              <li>
                <Link to={LANDING_LINKS.signIn} className={LINK}>
                  Sign in
                </Link>
              </li>
              <li>
                <Link to={LANDING_LINKS.register} className={LINK}>
                  Create account
                </Link>
              </li>
            </ul>
          </nav>
        </div>
      </div>
    </footer>
  )
}
