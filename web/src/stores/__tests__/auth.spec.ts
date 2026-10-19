import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setActivePinia, createPinia } from 'pinia';
import { useAuthStore } from '../auth';
import { api } from '@/api/client';

describe('auth store', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
  });

  it('initializes with unauthenticated state', () => {
    const store = useAuthStore();
    expect(store.isAuthenticated).toBe(false);
    expect(store.isAdmin).toBe(false);
    expect(store.user).toBeNull();
  });

  it('logs in successfully and sets user session', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      username: 'admin',
      role: 'admin',
    });

    const store = useAuthStore();
    const success = await store.login('admin', 'password');

    expect(success).toBe(true);
    expect(store.isAuthenticated).toBe(true);
    expect(store.isAdmin).toBe(true);
    expect(store.user?.username).toBe('admin');
  });

  it('handles login failure gracefully', async () => {
    vi.spyOn(api, 'login').mockRejectedValue(new Error('Invalid password'));

    const store = useAuthStore();
    const success = await store.login('admin', 'wrong');

    expect(success).toBe(false);
    expect(store.isAuthenticated).toBe(false);
    expect(store.error).toContain('Invalid password');
  });

  it('clears state upon logout', async () => {
    vi.spyOn(api, 'logout').mockResolvedValue({ success: true });

    const store = useAuthStore();
    store.user = { username: 'admin', role: 'admin' };
    expect(store.isAuthenticated).toBe(true);

    await store.logout();
    expect(store.isAuthenticated).toBe(false);
    expect(store.user).toBeNull();
  });
});
