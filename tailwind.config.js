/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./web/index.html', './web/src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        void: '#050505',
        charcoal: '#121212',
        cyan: '#00E5FF',
        amethyst: '#B388FF',
        crimson: '#FF1744',
      },
      fontFamily: {
        sans: ['"Inter Variable"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(0,229,255,0.25), 0 0 32px -8px rgba(0,229,255,0.35)',
        'glow-crimson': '0 0 0 1px rgba(255,23,68,0.3), 0 0 32px -8px rgba(255,23,68,0.4)',
      },
    },
  },
  plugins: [],
};
