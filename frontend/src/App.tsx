import { RouterProvider } from 'react-router-dom'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { router } from '@/router'

function App() {
  return (
    <TooltipProvider delayDuration={150}>
      <RouterProvider router={router} />
      <Toaster theme="dark" position="bottom-right" />
    </TooltipProvider>
  )
}

export default App
