import type { IndicatorType } from '@/api/types'

/**
 * Defang indicators for display so they can never be clicked or auto-linked:
 * 192.0.2[.]45 · evil[.]example · hxxps://evil[.]example/path
 */
export function defang(value: string, type: IndicatorType): string {
  if (type === 'HASH') return value
  if (type === 'URL') return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]')
  if (type === 'IP') return value.replace(/\.(?=\d+$)/, '[.]')
  return value.replace(/\./g, '[.]')
}

/** Shorten long hashes: sha256:7f3c9a1e…c7b3 */
export function shortHash(value: string): string {
  return value.length > 30 ? `${value.slice(0, 15)}…${value.slice(-4)}` : value
}
