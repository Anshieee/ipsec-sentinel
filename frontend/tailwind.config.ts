import type { Config } from 'tailwindcss'

const SANS = ['Geist Variable', 'Geist', 'Inter', 'ui-sans-serif', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif']
const MONO = ['"Geist Mono Variable"', '"Geist Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace']

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'rgb(var(--bg-rgb) / <alpha-value>)',
        'bg-elevated': 'rgb(var(--bg-elevated-rgb) / <alpha-value>)',
        'bg-card': 'rgb(var(--bg-card-rgb) / <alpha-value>)',
        'bg-hover': 'rgb(var(--bg-hover-rgb) / <alpha-value>)',
        'bg-input': 'rgb(var(--bg-input-rgb) / <alpha-value>)',
        border: 'rgb(var(--border-rgb) / <alpha-value>)',
        'border-subtle': 'rgb(var(--border-subtle-rgb) / <alpha-value>)',
        'border-strong': 'rgb(var(--border-strong-rgb) / <alpha-value>)',
        /* Range-slider track: neutral grey at >= 3:1 against card surface. */
        track: 'rgb(var(--color-track-rgb) / <alpha-value>)',
        'text-primary': 'rgb(var(--text-primary-rgb) / <alpha-value>)',
        'text-secondary': 'rgb(var(--text-secondary-rgb) / <alpha-value>)',
        /* #737373: large text, icons and decoration only (never small text). */
        'text-muted': 'rgb(var(--text-muted-rgb) / <alpha-value>)',
        /* #8a8a8a: small muted text (>= 4.5:1 on cards). */
        'text-muted-small': 'rgb(var(--text-muted-small-rgb) / <alpha-value>)',
        'text-disabled': 'rgb(var(--text-disabled-rgb) / <alpha-value>)',
        'white-accent': 'rgb(var(--white-accent-rgb) / <alpha-value>)',
        blue: 'rgb(var(--blue-rgb) / <alpha-value>)',
        green: 'rgb(var(--green-rgb) / <alpha-value>)',
        'green-bright': 'rgb(var(--green-bright-rgb) / <alpha-value>)',
        purple: 'rgb(var(--purple-rgb) / <alpha-value>)',
        orange: 'rgb(var(--orange-rgb) / <alpha-value>)',
        amber: 'rgb(var(--amber-rgb) / <alpha-value>)',
        red: 'rgb(var(--red-rgb) / <alpha-value>)',
        /* Okabe-Ito derived, re-tuned for dark; every entry >= 6.7:1 on base. */
        chart: {
          1: '#3888ec',
          2: '#189f70',
          3: '#ad59fc',
          4: '#f08020',
          5: '#f8a008',
          6: '#ff6467',
          7: '#8a8a8a',
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
        /* Cards carry their edge as a real 1px border (see Card); no glow. */
        card: 'none',
        focus: '0 0 0 2px var(--bg), 0 0 0 4px var(--blue)',
        overlay: 'var(--shadow-overlay), 0 0 0 1px var(--border)',
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
