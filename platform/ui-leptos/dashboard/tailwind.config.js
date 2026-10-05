/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.rs'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        accent: { DEFAULT: '#6366f1', hover: '#818cf8' },
        // Phase 7.1 — 6-token semantic palette. Backed by CSS
        // variables defined in input.css so light/dark/contrast
        // themes can swap the source of truth without touching
        // every utility class. New UI code SHOULD reach for these
        // tokens (e.g. `text-brand`, `bg-success/10`) instead of
        // raw Tailwind hues (`indigo-400`, `emerald-500`).
        brand:   { DEFAULT: 'rgb(var(--token-brand) / <alpha-value>)' },
        success: { DEFAULT: 'rgb(var(--token-success) / <alpha-value>)' },
        warn:    { DEFAULT: 'rgb(var(--token-warn) / <alpha-value>)' },
        danger:  { DEFAULT: 'rgb(var(--token-danger) / <alpha-value>)' },
        info:    { DEFAULT: 'rgb(var(--token-info) / <alpha-value>)' },
        muted:   { DEFAULT: 'rgb(var(--token-muted) / <alpha-value>)' },
      },
    },
  },
  // Dynamic plugin console modifiers (built via match arms / format in Rust).
  safelist: [
    'lc-console--devguard',
    'lc-console--tracetramp',
    'lc-console--witnessctl',
    'op-shell',
    'elev-1',
    'elev-2',
    'elev-3',
    'surface-panel',
    'mon-panel--economy',
    'mon-panel--security',
    'mon-panel--network',
    'mon-panel--load',
  ],
  plugins: [],
}
