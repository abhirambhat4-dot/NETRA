import { useLayoutEffect } from 'react'

const APP_THEME = 'netra-app-theme'

/**
 * Switches the document to the light authenticated-app theme while the
 * calling component is mounted. Applied to <html> (not a wrapper) so portalled
 * sheets, dialogs, menus and toasts pick up the same tokens; `dark` is removed
 * so shadcn `dark:` variants stay off. Restored on unmount, which keeps the
 * public register and password-recovery pages on their dark theme.
 */
export function useAppTheme() {
  useLayoutEffect(() => {
    const root = document.documentElement
    const hadDark = root.classList.contains('dark')
    root.classList.add(APP_THEME)
    root.classList.remove('dark')
    return () => {
      root.classList.remove(APP_THEME)
      if (hadDark) root.classList.add('dark')
    }
  }, [])
}
