import { ref, onMounted, getCurrentInstance } from 'vue';

export type ThemeMode = 'dark' | 'light' | 'system';

const STORAGE_KEY = 'raiwall_theme';
const theme = ref<ThemeMode>('dark');
const isDark = ref<boolean>(true);

function updateDOM(dark: boolean) {
  isDark.value = dark;
  if (typeof document !== 'undefined') {
    if (dark) {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.classList.add('light');
    }
  }
}

function resolveSystemPreference(): boolean {
  if (typeof window !== 'undefined' && window.matchMedia) {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  return true;
}

function applyTheme(mode: ThemeMode) {
  theme.value = mode;
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, mode);
  }

  if (mode === 'system') {
    updateDOM(resolveSystemPreference());
  } else {
    updateDOM(mode === 'dark');
  }
}

// Immediately synchronize at module load time if running in browser
if (typeof localStorage !== 'undefined') {
  try {
    const stored = localStorage.getItem(STORAGE_KEY) as ThemeMode | null;
    if (stored && ['dark', 'light', 'system'].includes(stored)) {
      theme.value = stored;
      if (stored === 'system') {
        updateDOM(resolveSystemPreference());
      } else {
        updateDOM(stored === 'dark');
      }
    }
  } catch {
    // ignore
  }
}

export function useTheme() {
  const initTheme = () => {
    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem(STORAGE_KEY) as ThemeMode | null;
      if (stored && ['dark', 'light', 'system'].includes(stored)) {
        applyTheme(stored);
        return;
      }
    }
    // Default to dark mode for enterprise security console
    applyTheme('dark');
  };

  const toggleTheme = () => {
    const nextMode: ThemeMode = isDark.value ? 'light' : 'dark';
    applyTheme(nextMode);
  };

  const setTheme = (mode: ThemeMode) => {
    applyTheme(mode);
  };

  if (getCurrentInstance()) {
    onMounted(() => {
      initTheme();

      if (typeof window !== 'undefined' && window.matchMedia) {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        const listener = (e: MediaQueryListEvent) => {
          if (theme.value === 'system') {
            updateDOM(e.matches);
          }
        };
        if (mediaQuery.addEventListener) {
          mediaQuery.addEventListener('change', listener);
        }
      }
    });
  } else {
    initTheme();
  }

  return {
    theme,
    isDark,
    toggleTheme,
    setTheme,
    initTheme,
  };
}
