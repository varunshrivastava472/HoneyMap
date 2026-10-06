/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#FAFAF9", // Warm off-white canvas
        foreground: "#0F172A", // Deep charcoal ink
        canvas: "#FAFAF9",
        card: {
          DEFAULT: "#FFFFFF",
          foreground: "#0F172A",
          muted: "#F8FAFC",
          hover: "#F1F5F9",
        },
        border: {
          DEFAULT: "#E2E8F0", // Clean hairline border
          subtle: "#F1F5F9",
          hover: "#CBD5E1",
          active: "#10B981",
        },
        ink: {
          primary: "#0F172A", // High contrast
          secondary: "#334155", // Medium contrast
          muted: "#64748B", // Muted labels & timestamps
          faint: "#94A3B8",
        },
        brand: {
          50: "#ECFDF5",
          100: "#D1FAE5",
          200: "#A7F3D0",
          500: "#10B981",
          600: "#059669",
          700: "#047857",
          900: "#064E3B",
        },
        warning: {
          50: "#FFF7ED",
          100: "#FFEDD5",
          200: "#FED7AA",
          500: "#F97316",
          600: "#EA580C",
          700: "#C2410C",
        },
        danger: {
          50: "#FEF2F2",
          100: "#FEE2E2",
          200: "#FECACA",
          500: "#EF4444",
          600: "#DC2626",
          700: "#B91C1C",
        },
        severity: {
          low: {
            bg: "#F1F5F9",
            text: "#334155",
            border: "#CBD5E1",
          },
          medium: {
            bg: "#FEF3C7",
            text: "#92400E",
            border: "#FDE68A",
          },
          high: {
            bg: "#FFEDD5",
            text: "#9A3412",
            border: "#FED7AA",
          },
          critical: {
            bg: "#FEE2E2",
            text: "#991B1B",
            border: "#FECACA",
          },
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.04)',
        'card-hover': '0 4px 12px -2px rgba(0, 0, 0, 0.06), 0 2px 6px -2px rgba(0, 0, 0, 0.03)',
        'dropdown': '0 10px 25px -4px rgba(0, 0, 0, 0.08), 0 4px 8px -2px rgba(0, 0, 0, 0.04)',
        'drawer': '-4px 0 24px -2px rgba(0, 0, 0, 0.08)',
        'pill': '0 1px 2px 0 rgba(0, 0, 0, 0.03)',
      },
      borderRadius: {
        'xl': '12px',
        '2xl': '16px',
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-in-right': 'slideInRight 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(2px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideInRight: {
          '0%': { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
};
