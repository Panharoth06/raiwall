import { describe, it, expect, beforeEach } from 'vitest';
import { useTheme } from '../useTheme';

const storageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, value: string) => {
      store[key] = value.toString();
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

if (typeof window !== 'undefined') {
  Object.defineProperty(window, 'localStorage', {
    value: storageMock,
    writable: true,
  });
}

describe('useTheme', () => {
  beforeEach(() => {
    window.localStorage.clear();
    if (typeof document !== 'undefined') {
      document.documentElement.className = '';
    }
  });

  it('initializes to dark mode by default', () => {
    const { isDark, theme, initTheme } = useTheme();
    initTheme();
    expect(isDark.value).toBe(true);
    expect(theme.value).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('toggles between dark and light mode', () => {
    const { isDark, toggleTheme, initTheme } = useTheme();
    initTheme();
    expect(isDark.value).toBe(true);

    toggleTheme();
    expect(isDark.value).toBe(false);
    expect(document.documentElement.classList.contains('light')).toBe(true);
    expect(document.documentElement.classList.contains('dark')).toBe(false);

    toggleTheme();
    expect(isDark.value).toBe(true);
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('persists selected theme in localStorage', () => {
    const { setTheme } = useTheme();
    setTheme('light');
    expect(window.localStorage.getItem('raiwall_theme')).toBe('light');

    setTheme('dark');
    expect(window.localStorage.getItem('raiwall_theme')).toBe('dark');
  });
});
