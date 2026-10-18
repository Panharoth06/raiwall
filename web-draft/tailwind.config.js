/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    './index.html',
    './src/**/*.{vue,js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#080A0C',
        rail: '#11141A',
        surface: '#1E222A',
        'surface-border': '#363D4C',
        brand: '#FFC000',
        activeBlue: '#2574F5',
        cleanEmerald: '#10B981',
        threatRed: '#EF4444',
        subtext: '#848D9C',
        subhead: '#B0B8C4',
      },
    },
  },
  plugins: [],
}
