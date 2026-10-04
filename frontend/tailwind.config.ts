import type { Config } from 'tailwindcss'

const SANS = ['Geist Variable', 'Geist', 'Inter', 'ui-sans-serif', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif']
const MONO = ['"Geist Mono Variable"', '"Geist Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace']

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: 'rgb(var(--color-base-rgb) / <alpha-value>)',
        /* Glass rungs: the channel is the tint, --glass-* carries the opacity. */
        surface: 'rgb(var(--color-surface-rgb) / calc(<alpha-value> * var(--glass-surface)))',
        raised: 'rgb(var(--color-raised-rgb) / calc(<alpha-value> * var(--glass-raised)))',
        line: 'rgb(var(--color-line-rgb) / calc(<alpha-value> * var(--glass-line)))',
        'line-strong': 'rgb(var(--color-line-strong-rgb) / calc(<alpha-value> * var(--glass-line-strong)))',
        /* Range-slider track: neutral grey at >= 3:1 against card surface. */
        track: 'rgb(var(--color-track-rgb) / <alpha-value>)',
        ink: 'rgb(var(--color-ink-rgb) / <alpha-value>)',
        muted: 'rgb(var(--color-muted-rgb) / <alpha-value>)',
        /* Label colour for a light fill (the hover step of a filled button).
           Separate from `base` because `text-base` is the 14/20 font-size role. */
        'ink-inverse': 'rgb(var(--color-base-rgb) / <alpha-value>)',
        accent: 'rgb(var(--color-accent-rgb) / <alpha-value>)',
        'accent-solid': 'rgb(var(--color-accent-solid-rgb) / <alpha-value>)',
        highlight: 'rgb(var(--color-highlight-rgb) / <alpha-value>)',
        safe: 'rgb(var(--color-safe-rgb) / <alpha-value>)',
        warn: 'rgb(var(--color-warn-rgb) / <alpha-value>)',
        danger: 'rgb(var(--color-danger-rgb) / <alpha-value>)',
        'danger-solid': 'rgb(var(--color-danger-solid-rgb) / <alpha-value>)',
        orange: 'rgb(var(--color-orange-rgb) / <alpha-value>)',
        violet: 'rgb(var(--color-violet-rgb) / <alpha-value>)',
        /* Okabe-Ito derived, re-tuned for dark; every entry >= 6.7:1 on base. */
        chart: {
          1: '#5A9BF8',
          2: '#41C7E8',
          3: '#3FC98F',
          4: '#EBB13C',
          5: '#B79DF3',
          6: '#EE8260',
          7: '#93A3B4',
        },
      },
      fontFamily: {
        sans: SANS,
        mono: MONO,
      },
      fontSize: {
        // role: size / line-height  (DESIGN.md > Typography)
        '2xs': ['11px', '14px'], // overline / badge micro
        xs: ['12px', '16px'], // caption
        sm: ['13px', '20px'], // body
        base: ['14px', '20px'], // card + section title
        lg: ['16px', '24px'],
        xl: ['20px', '28px'], // page title
        'kpi': ['28px', '32px'], // KPI number
      },
      letterSpacing: {
        tighter: '-0.02em',
        tight: '-0.011em',
        snug: '-0.006em',
        wide: '0.04em',
        wider: '0.08em',
      },
      borderRadius: {
        card: '10px',
        control: '6px',
        cell: '4px',
      },
      boxShadow: {
        card: '0 0 0 1px var(--color-line), inset 0 1px 0 0 rgb(255 255 255 / 0.05)',
        focus: '0 0 0 2px var(--color-base), 0 0 0 4px var(--color-accent)',
        overlay: 'var(--shadow-overlay), 0 0 0 1px var(--color-line), inset 0 1px 0 0 rgb(255 255 255 / 0.06)',
      },
      spacing: {
        header: '56px',
        sidebar: '248px',
        'sidebar-rail': '64px',
        drawer: '560px',
      },
      transitionDuration: {
        fast: '140ms',
        base: '180ms',
        slow: '240ms',
      },
      transitionTimingFunction: {
        out: 'cubic-bezier(0.2, 0, 0, 1)',
        inout: 'cubic-bezier(0.4, 0, 0.2, 1)',
      },
      zIndex: {
        sticky: '100',
        header: '200',
        dropdown: '300',
        overlay: '400',
        drawer: '450',
        tooltip: '500',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-400px 0' },
          '100%': { backgroundPosition: '400px 0' },
        },
      },
      animation: {
        shimmer: 'shimmer 1.4s linear infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
