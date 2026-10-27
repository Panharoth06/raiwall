/**
 * Bridges the CSS design-token contract in `style.css` to renderers that cannot
 * resolve `var()` themselves (ECharts canvas, cobe WebGL, inline tooltip HTML).
 *
 * Every color in the application must originate from a token in `style.css`.
 * Tokens are stored as bare HSL triplets (`H S% L%`) so alpha can be composed
 * at the call site.
 */

const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined'

/** Raw token triplet, e.g. `"0 0% 10%"`. Empty string outside the browser. */
export function tokenTriplet(name: string): string {
  if (!isBrowser) return ''
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

/** CSS expression for SVG/HTML attributes: `hsl(var(--token))`. */
export function cssToken(name: string, alpha?: number): string {
  return alpha === undefined ? `hsl(var(${name}))` : `hsl(var(${name}) / ${alpha})`
}

/** Concrete color string for canvas renderers, e.g. `hsl(0 0% 10% / 0.96)`. */
export function canvasColor(name: string, alpha?: number): string {
  const triplet = tokenTriplet(name)
  if (!triplet) return 'transparent'
  return alpha === undefined ? `hsl(${triplet})` : `hsl(${triplet} / ${alpha})`
}

/**
 * Token resolved to normalized RGB (0..1) for WebGL uniforms.
 * Resolution goes through the browser's own color parser to avoid
 * re-implementing HSL conversion.
 */
export function tokenRgb01(name: string): [number, number, number] {
  const triplet = tokenTriplet(name)
  if (!isBrowser || !triplet) return [0, 0, 0]

  const probe = document.createElement('span')
  probe.style.color = `hsl(${triplet})`
  document.body.appendChild(probe)
  const resolved = getComputedStyle(probe).color
  probe.remove()

  const channels = resolved.match(/[\d.]+/g)
  if (!channels || channels.length < 3) return [0, 0, 0]

  return [
    Number(channels[0]) / 255,
    Number(channels[1]) / 255,
    Number(channels[2]) / 255,
  ]
}
