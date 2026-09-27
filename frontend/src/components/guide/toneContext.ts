import { createContext, useContext, useEffect } from 'react'
import type { GuideTone } from '@/lib/guide'

interface GuideToneState {
  tone: GuideTone
  setTone: (tone: GuideTone) => void
}

export const GuideToneContext = createContext<GuideToneState>({ tone: 'normal', setTone: () => {} })

export function useGuideToneState() {
  return useContext(GuideToneContext)
}

/** Declare the page's alert level; resets to normal when the page unmounts. */
export function useGuideTone(tone: GuideTone) {
  const { setTone } = useContext(GuideToneContext)
  useEffect(() => {
    setTone(tone)
    return () => setTone('normal')
  }, [tone, setTone])
}
