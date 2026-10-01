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
      <div className="relative min-h-svh bg-background text-foreground">
        <div aria-hidden className="pointer-events-none fixed inset-0 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(56,217,255,0.12),transparent_28%),radial-gradient(circle_at_80%_10%,_rgba(79,124,255,0.12),transparent_24%)]" />
          <div className="netra-grid absolute inset-0 opacity-35" />
          <div className="absolute -top-16 left-12 h-72 w-72 rounded-full bg-primary/10 blur-3xl" />
          <div className="absolute top-0 right-0 h-80 w-80 rounded-full bg-violet/10 blur-3xl" />
        </div>

        <aside className="fixed inset-y-0 left-0 z-40 hidden w-[88px] border-r border-sidebar-border bg-sidebar/75 backdrop-blur-xl md:block lg:w-64">
          <Sidebar />
        </aside>

        <Sheet open={navOpen} onOpenChange={setNavOpen}>
          <SheetContent side="left" className="w-72 gap-0 border-sidebar-border bg-sidebar/95 p-0 shadow-2xl sm:max-w-72" showCloseButton={false}>
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SheetDescription className="sr-only">NETRA main navigation</SheetDescription>
            <Sidebar mode="expanded" onNavigate={() => setNavOpen(false)} />
          </SheetContent>
        </Sheet>

        <div className="relative md:pl-[88px] lg:pl-64">
          <Header onOpenNav={() => setNavOpen(true)} />
          <main className="mx-auto w-full max-w-[1680px] px-4 pt-5 pb-24 md:px-6 lg:px-8 lg:pt-6 lg:pb-28">
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
