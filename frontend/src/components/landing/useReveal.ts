import { useLayoutEffect, type RefObject } from 'react'

/**
 * Reveals `[data-reveal]` elements inside `root` once, as they scroll into view.
 *
 * Content is visible by default: elements are hidden only after `.nl-js` is added here, before
 * the first paint. With reduced motion, or without IntersectionObserver, everything is revealed
 * immediately. Each element is unobserved after its reveal, so it never animates twice.
 */
export function useReveal(root: RefObject<HTMLElement | null>) {
  useLayoutEffect(() => {
    const el = root.current
    if (!el) return

    const targets = Array.from(el.querySelectorAll<HTMLElement>('[data-reveal]'))
    const reveal = (target: Element) => target.setAttribute('data-revealed', 'true')
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    if (reduced || typeof IntersectionObserver === 'undefined') {
      targets.forEach(reveal)
      return
    }

    el.classList.add('nl-js')
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue
          reveal(entry.target)
          observer.unobserve(entry.target)
        }
      },
      { rootMargin: '0px 0px -8% 0px', threshold: 0.12 },
    )
    targets.forEach((target) => observer.observe(target))

    return () => {
      observer.disconnect()
      el.classList.remove('nl-js')
    }
  }, [root])
}
