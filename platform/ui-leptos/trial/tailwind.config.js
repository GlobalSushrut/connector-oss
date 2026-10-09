/** @type {import('tailwindcss').Config} */
// Mirrors ../dashboard/tailwind.config.js so the trial page renders
// identically to the dashboard's trial/login pages.
module.exports = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.rs'],
  // Selector buttons build classes like `border-emerald-500` from format!()
  // strings, which the Tailwind scanner can't see — safelist them.
  safelist: [
    'border-emerald-500', 'border-amber-500', 'border-indigo-500',
    'bg-emerald-500', 'bg-amber-500', 'bg-indigo-500',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        accent: { DEFAULT: '#6366f1', hover: '#818cf8' },
        brand:   { DEFAULT: 'rgb(var(--token-brand) / <alpha-value>)' },
        success: { DEFAULT: 'rgb(var(--token-success) / <alpha-value>)' },
        warn:    { DEFAULT: 'rgb(var(--token-warn) / <alpha-value>)' },
        danger:  { DEFAULT: 'rgb(var(--token-danger) / <alpha-value>)' },
        info:    { DEFAULT: 'rgb(var(--token-info) / <alpha-value>)' },
        muted:   { DEFAULT: 'rgb(var(--token-muted) / <alpha-value>)' },
      },
    },
  },
  plugins: [],
}
