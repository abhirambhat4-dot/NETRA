import { useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { GuideToneProvider, NetraGuide } from '@/components/guide'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import { useAppTheme } from './useAppTheme'

/** Authenticated application shell: sidebar, header, page outlet, guide. */
export function AppLayout() {
  useAppTheme()
  const [navOpen, setNavOpen] = useState(false)
  const { pathname } = useLocation()

  return (
    <GuideToneProvider>
      <div className="relative min-h-svh bg-background text-foreground">
        {/* A single soft wash behind the header keeps the canvas from feeling flat. */}
        <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-72 bg-linear-to-b from-primary/[0.035] to-transparent" />

        <aside className="fixed inset-y-0 left-0 z-40 hidden w-[76px] border-r border-sidebar-border bg-sidebar md:block lg:w-64">
          <Sidebar />
        </aside>

        <Sheet open={navOpen} onOpenChange={setNavOpen}>
          <SheetContent side="left" className="w-72 gap-0 border-sidebar-border bg-sidebar p-0 shadow-xl sm:max-w-72" showCloseButton={false}>
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SheetDescription className="sr-only">NETRA main navigation</SheetDescription>
            <Sidebar mode="expanded" onNavigate={() => setNavOpen(false)} />
          </SheetContent>
        </Sheet>

        <div className="relative md:pl-[76px] lg:pl-64">
          <Header onOpenNav={() => setNavOpen(true)} />
          <main className="mx-auto w-full max-w-[1600px] px-4 pt-6 pb-24 md:px-6 lg:px-8 lg:pt-7 lg:pb-28">
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
