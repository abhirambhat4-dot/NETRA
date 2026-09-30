import { RouterProvider } from 'react-router-dom'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { AuthProvider } from '@/auth/AuthProvider'
import { router } from '@/router'

function App() {
  return (
    <AuthProvider>
      <TooltipProvider delayDuration={150}>
        <RouterProvider router={router} />
        {/* Offset clears the NETRA Guide robot docked bottom-right */}
        <Toaster theme="dark" position="bottom-right" offset={{ bottom: 92, right: 20 }} mobileOffset={{ bottom: 76, right: 12 }} />
      </TooltipProvider>
    </AuthProvider>
  )
}

export default App
