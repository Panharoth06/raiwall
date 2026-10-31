import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import NavbarAdminProfile from '../NavbarAdminProfile.vue';
import { useAuthStore } from '@/stores/auth';

const mockPush = vi.fn();

vi.mock('@/router', () => ({
  useRouter: () => ({
    push: mockPush,
  }),
}));

describe('NavbarAdminProfile.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mockPush.mockClear();
  });

  it('renders user initials, username, and role badge', () => {
    const authStore = useAuthStore();
    authStore.user = {
      id: 'usr-1',
      username: 'secops',
      role: 'admin',
      created_at: '2026-01-01T00:00:00Z',
    };

    const wrapper = mount(NavbarAdminProfile);
    expect(wrapper.text()).toContain('SE');
    expect(wrapper.text()).toContain('secops');
    expect(wrapper.text()).toContain('admin');
  });

  it('triggers logout and redirects to login when logout button is clicked', async () => {
    const authStore = useAuthStore();
    const logoutSpy = vi.spyOn(authStore, 'logout').mockResolvedValue();

    const wrapper = mount(NavbarAdminProfile);
    const logoutBtn = wrapper.find('[data-testid="logout-btn"]');
    expect(logoutBtn.exists()).toBe(true);

    await logoutBtn.trigger('click');
    expect(logoutSpy).toHaveBeenCalled();
    expect(mockPush).toHaveBeenCalledWith('/login');
  });
});
