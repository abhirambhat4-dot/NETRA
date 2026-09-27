import { useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { GuideToneProvider, NetraGuide } from '@/components/guide'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Header } from './Header'
import { Sidebar } from './Sidebar'

/** Authenticated application shell: atmosphere, sidebar, header, page outlet, guide. */
export function AppLayout() {
  const [navOpen, setNavOpen] = useState(false)
  const { pathname } = useLocation()

  return (
    <GuideToneProvider>
      <div className="relative min-h-svh bg-background">
        {/* Background atmosphere */}
        <div aria-hidden className="netra-atmosphere pointer-events-none fixed inset-0" />
        <div aria-hidden className="netra-grid pointer-events-none fixed inset-0" />

        {/* Sidebar: icon rail on tablet, full on desktop */}
        <aside className="fixed inset-y-0 left-0 z-40 hidden w-16 border-r border-sidebar-border backdrop-blur-xl md:block lg:w-58">
          <Sidebar />
        </aside>

        {/* Mobile drawer */}
        <Sheet open={navOpen} onOpenChange={setNavOpen}>
          <SheetContent side="left" className="w-64 gap-0 border-sidebar-border bg-sidebar p-0 sm:max-w-64" showCloseButton={false}>
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SheetDescription className="sr-only">NETRA main navigation</SheetDescription>
            <Sidebar mode="expanded" onNavigate={() => setNavOpen(false)} />
          </SheetContent>
        </Sheet>

        <div className="relative md:pl-16 lg:pl-58">
          <Header onOpenNav={() => setNavOpen(true)} />
          {/* Bottom padding keeps the last content scrollable clear of the NETRA Guide robot */}
          <main className="mx-auto w-full max-w-[1680px] px-4 pt-6 pb-24 md:px-6 lg:px-8 lg:pt-7 lg:pb-28">
            {/* keyed so each page gets a gentle entrance */}
            <div key={pathname} className="animate-in duration-300 fade-in-0 slide-in-from-bottom-1 motion-reduce:slide-in-from-bottom-0">
              <Outlet />
            </div>
          </main>
        </div>

        <NetraGuide />
      </div>
    </GuideToneProvider>
  )
}
