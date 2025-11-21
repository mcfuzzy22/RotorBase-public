/** @type {import('tailwindcss').Config} */
const withOpacity = (variable) => ({ opacityValue }) =>
  opacityValue === undefined
    ? `rgb(var(${variable}))`
    : `rgb(var(${variable}) / ${opacityValue})`;

module.exports = {
  darkMode: 'class',
  content: [
    './Components/**/*.{razor,cshtml,html}',
    './Pages/**/*.{razor,cshtml,html}',
    './wwwroot/**/*.{html,js,ts}'
  ],
  theme: {
    container: { center: true, padding: '1rem' },
    extend: {
      fontFamily: {
        sans: [
          'Inter var',
          'ui-sans-serif',
          'system-ui',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'Noto Sans',
          'Apple Color Emoji',
          'Segoe UI Emoji'
        ],
        mono: [
          'JetBrains Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'Liberation Mono',
          'monospace'
        ]
      },
      colors: {
        background: withOpacity('--color-bg'),
        surface: withOpacity('--color-surface'),
        muted: withOpacity('--color-muted'),
        border: withOpacity('--color-border'),
        foreground: withOpacity('--color-fg'),
        primary: withOpacity('--color-primary'),
        'primary-foreground': withOpacity('--color-primary-fg'),
        secondary: withOpacity('--color-secondary'),
        accent: withOpacity('--color-accent'),
        success: withOpacity('--color-success'),
        warning: withOpacity('--color-warning'),
        danger: withOpacity('--color-danger'),
        info: withOpacity('--color-info')
      },
      borderRadius: {
        md: '0.6rem',
        lg: '1rem',
        xl: '1.25rem'
      },
      boxShadow: {
        sm: '0 1px 2px rgb(0 0 0 / 0.06)',
        DEFAULT: '0 2px 10px rgb(0 0 0 / 0.08), 0 1px 3px rgb(0 0 0 / 0.06)',
        lg: '0 10px 25px rgb(0 0 0 / 0.12), 0 2px 8px rgb(0 0 0 / 0.08)',
        'inner-lg': 'inset 0 1px 0 rgb(255 255 255 / 0.15)'
      },
      ringColor: {
        DEFAULT: 'rgb(var(--color-primary) / 0.55)'
      },
      keyframes: {
        gradient: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' }
        },
        shimmer: {
          '0%': { backgroundPosition: '200% 0' },
          '100%': { backgroundPosition: '-200% 0' }
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-4px)' }
        },
        accordionDown: {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' }
        },
        accordionUp: {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' }
        }
      },
      animation: {
        gradient: 'gradient 10s ease infinite',
        shimmer: 'shimmer 2.5s linear infinite',
        float: 'float 4s ease-in-out infinite',
        'accordion-down': 'accordionDown 200ms ease-out',
        'accordion-up': 'accordionUp 200ms ease-out'
      },
      backgroundImage: {
        grid: 'linear-gradient(to right, rgb(var(--color-border) / 0.25) 1px, transparent 1px), linear-gradient(to bottom, rgb(var(--color-border) / 0.25) 1px, transparent 1px)',
        radial: 'radial-gradient(60% 60% at 50% 50%, rgb(var(--color-primary) / 0.08), transparent)',
        dot: 'radial-gradient(circle at center, rgb(var(--color-fg) / 0.12) 1px, transparent 1.5px)'
      },
      backgroundSize: {
        grid: '24px 24px',
        shimmer: '200% 100%'
      }
    }
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography')
  ]
};
