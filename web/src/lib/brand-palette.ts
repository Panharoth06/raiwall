/**
 * Raiwall brand artwork palette.
 *
 * The logo is a fixed brand asset: it must render identically in light and dark
 * mode, so these values are intentionally theme-invariant and live outside the
 * semantic token contract in `style.css`. Name them here instead of inlining
 * hex literals in component markup.
 */
export const brandPalette = {
  rimLight: '#38BDF8',
  rimMid: '#2574F5',
  rimDeep: '#0284C7',
  shieldTop: '#14244B',
  shieldMid: '#0D162B',
  shieldDeep: '#070C18',
  mascotLight: '#38E1FF',
  mascotDeep: '#00A3FF',
  snout: '#00D2FF',
  highlight: '#FFFFFF',
  wallLight: '#BAE6FD',
} as const

export type BrandPalette = typeof brandPalette
