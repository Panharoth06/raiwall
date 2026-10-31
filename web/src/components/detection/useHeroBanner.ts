import { ref } from 'vue';

export function useHeroBanner(storageKey: string) {
  const getIsDismissed = (): boolean => {
    if (typeof localStorage === 'undefined') return false;
    try {
      return localStorage.getItem(`raiwall_hero_dismissed_${storageKey}`) === 'true';
    } catch {
      return false;
    }
  };

  // Synchronous initial value prevents layout flash/flicker on mount
  const showHero = ref(!getIsDismissed());

  const toggleHero = () => {
    showHero.value = !showHero.value;
  };

  const dismissHero = () => {
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(`raiwall_hero_dismissed_${storageKey}`, 'true');
      } catch {
        // storage disabled or quota exceeded
      }
    }
    showHero.value = false;
  };

  const reopenHero = () => {
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.removeItem(`raiwall_hero_dismissed_${storageKey}`);
      } catch {
        // storage disabled
      }
    }
    showHero.value = true;
  };

  const closeTemporary = () => {
    showHero.value = false;
  };

  return {
    showHero,
    toggleHero,
    dismissHero,
    reopenHero,
    closeTemporary,
  };
}
