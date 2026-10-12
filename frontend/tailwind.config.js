/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0F172A',
          card: '#1E293B',
          border: '#334155',
          muted: '#64748B',
          text: '#F8FAFC',
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#3B82F6',
          info: '#64748B',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
