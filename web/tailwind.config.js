/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    './index.html',
    './src/**/*.{vue,js,ts,jsx,tsx}',
  ],
  theme: {
    boxShadow: {
      none: 'none',
      sm: 'none',
      DEFAULT: 'none',
      md: 'none',
      lg: 'none',
      xl: 'none',
      '2xl': 'none',
      inner: 'none',
    },
    dropShadow: {
      none: 'none',
      sm: 'none',
      DEFAULT: 'none',
      md: 'none',
      lg: 'none',
      xl: 'none',
      '2xl': 'none',
    },
    extend: {
      fontFamily: {
        sans: [
          'Google Sans',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'sans-serif',
        ],
      },
      colors: {
        // Semantic CSS Variable Tokens (shadcn-vue standard)
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },

        // Security Domain Tokens (First-Class WAF Semantics)
        threat: {
          DEFAULT: 'hsl(var(--threat))',
          foreground: 'hsl(var(--threat-foreground))',
        },
        success: {
          DEFAULT: 'hsl(var(--success))',
          foreground: 'hsl(var(--success-foreground))',
        },
        warning: {
          DEFAULT: 'hsl(var(--warning))',
          foreground: 'hsl(var(--warning-foreground))',
        },
        info: {
          DEFAULT: 'hsl(var(--info))',
          foreground: 'hsl(var(--info-foreground))',
        },

        // Instrument & Data-Viz Tokens
        'accent-blue': 'hsl(var(--accent-blue))',
        'threat-emphasis': 'hsl(var(--threat-emphasis))',
        'success-emphasis': 'hsl(var(--success-emphasis))',
        'info-emphasis': 'hsl(var(--info-emphasis))',
        diagram: {
          text: 'hsl(var(--diagram-text))',
          muted: 'hsl(var(--diagram-text-muted))',
          subtle: 'hsl(var(--diagram-text-subtle))',
          guide: 'hsl(var(--diagram-guide))',
          node: 'hsl(var(--diagram-node))',
          'node-elevated': 'hsl(var(--diagram-node-elevated))',
          'node-hover': 'hsl(var(--diagram-node-hover))',
          'node-border': 'hsl(var(--diagram-node-border))',
          hub: 'hsl(var(--diagram-hub))',
          'hub-muted': 'hsl(var(--diagram-hub-muted))',
          'hub-border': 'hsl(var(--diagram-hub-border))',
          'node-info': 'hsl(var(--diagram-node-info))',
          'node-success': 'hsl(var(--diagram-node-success))',
          'map-land': 'hsl(var(--diagram-map-land))',
          'map-border': 'hsl(var(--diagram-map-border))',
        },
        chart: {
          1: 'hsl(var(--chart-1))',
          2: 'hsl(var(--chart-2))',
          3: 'hsl(var(--chart-3))',
          4: 'hsl(var(--chart-4))',
          5: 'hsl(var(--chart-5))',
          6: 'hsl(var(--chart-6))',
          7: 'hsl(var(--chart-7))',
          8: 'hsl(var(--chart-8))',
        },
      },
      borderRadius: {
        lg: 'var(--radius, 0.5rem)',
        md: 'calc(var(--radius, 0.5rem) - 2px)',
        sm: 'calc(var(--radius, 0.5rem) - 4px)',
      },
    },
  },
  plugins: [],
}
