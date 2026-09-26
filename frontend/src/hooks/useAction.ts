import { useState } from 'react'
import { toast } from 'sonner'

/** Runs a service mutation with busy state and success / error toasts. */
export function useAction() {
  const [busy, setBusy] = useState<string | null>(null)

  async function run<T>(key: string, action: () => Promise<T>, success: string): Promise<T | undefined> {
    setBusy(key)
    try {
      const result = await action()
      toast.success(success)
      return result
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Action failed')
      return undefined
    } finally {
      setBusy(null)
    }
  }

  return { busy, run }
}
