import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { api, type UserSession } from '@/api/client';

export const useAuthStore = defineStore('auth', () => {
  const user = ref<UserSession | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const isAuthenticated = computed(() => user.value !== null);
  const isAdmin = computed(() => user.value?.role === 'admin');

  async function fetchCurrentUser() {
    loading.value = true;
    error.value = null;
    try {
      const data = await api.getMe();
      user.value = data;
    } catch {
      user.value = null;
    } finally {
      loading.value = false;
    }
  }

  async function login(username: string, password: string) {
    loading.value = true;
    error.value = null;
    try {
      const data = await api.login({ username, password });
      user.value = data;
      return true;
    } catch (err: unknown) {
      error.value = err instanceof Error ? err.message : 'Login failed';
      return false;
    } finally {
      loading.value = false;
    }
  }

  async function logout() {
    try {
      await api.logout();
    } catch {
      // ignore
    } finally {
      user.value = null;
    }
  }

  return {
    user,
    loading,
    error,
    isAuthenticated,
    isAdmin,
    fetchCurrentUser,
    login,
    logout,
  };
});
