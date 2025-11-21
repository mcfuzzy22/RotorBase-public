/* Minimal theme toggle with brand modes */
(function () {
  const LS_KEY = 'theme';
  const BRAND_KEY = 'theme-brand';
  const prefers = window.matchMedia('(prefers-color-scheme: dark)');

  function apply(input) {
    const targets = [document.documentElement, document.body].filter(Boolean);
    const theme = input || localStorage.getItem(LS_KEY) || 'system';

    const run = () => {
      for (const el of targets) {
        el.classList.remove('dark');
      }
      document.documentElement.removeAttribute('data-theme');

      const useDark = theme === 'dark' || (theme === 'system' && prefers.matches);
      if (useDark) {
        for (const el of targets) {
          el.classList.add('dark');
        }
      }

      const brand = localStorage.getItem(BRAND_KEY);
      if (brand) {
        document.documentElement.setAttribute('data-theme', brand);
      }
    };

    run();
    queueMicrotask(run);
    requestAnimationFrame(run);
    setTimeout(run, 50);
  }

  window.theme = {
    current: () => localStorage.getItem(LS_KEY) || 'system',
    set: (theme) => {
      localStorage.setItem(LS_KEY, theme);
      apply(theme);
    },
    toggleDark: () => {
      const next = window.theme.current() === 'dark' ? 'light' : 'dark';
      window.theme.set(next);
    },
    applyCurrent: () => apply(),
    setBrand: (brand) => {
      if (brand) {
        localStorage.setItem(BRAND_KEY, brand);
      } else {
        localStorage.removeItem(BRAND_KEY);
      }
      apply();
    }
  };

  prefers.addEventListener?.('change', () => {
    if ((localStorage.getItem(LS_KEY) || 'system') === 'system') {
      apply();
    }
  });

  window.addEventListener('storage', (event) => {
    if (event.key === LS_KEY || event.key === BRAND_KEY) {
      apply();
    }
  });

  apply();

  window.rbToggleTheme = () => window.theme?.toggleDark?.();
})();
