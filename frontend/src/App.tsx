import { ShieldCheck } from 'lucide-react'

// Temporary foundation check — replaced by the router in the routing step.
function App() {
  return (
    <div className="flex min-h-screen items-center justify-center gap-3 bg-background text-foreground">
      <ShieldCheck className="size-8" />
      <h1 className="text-2xl font-semibold tracking-widest">NETRA</h1>
    </div>
  )
}

export default App
