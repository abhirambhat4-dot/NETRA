import type * as React from 'react'
import { useState } from 'react'
import type { GuideTone } from '@/lib/guide'
import { GuideToneContext } from './toneContext'

/** Lets pages raise the robot to a warning / critical state while they are shown. */
export function GuideToneProvider({ children }: { children: React.ReactNode }) {
  const [tone, setTone] = useState<GuideTone>('normal')
  return <GuideToneContext.Provider value={{ tone, setTone }}>{children}</GuideToneContext.Provider>
}
