import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import DashboardLayout from '../DashboardLayout.vue';
import { ref } from 'vue';

const mockRoute = ref({ path: '/statistics', fullPath: '/statistics', name: 'statistics', params: {}, query: {} });
const mockPush = vi.fn();

vi.mock('@/router', () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({
    push: mockPush,
  }),
}));

describe('DashboardLayout.vue (Task 74)', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mockRoute.value = { path: '/statistics', fullPath: '/statistics', name: 'statistics', params: {}, query: {} };
    mockPush.mockClear();
  });

  it('renders all 8 SafeLine core domains plus 3D Topology navigation links', () => {
    const wrapper = mount(DashboardLayout, {
      slots: {
        default: '<div data-testid="test-content">Main View Content</div>',
      },
    });

    expect(wrapper.find('[data-testid="nav-statistics"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-applications"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-attacks"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-allow-deny"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-http-flood"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-anti-bot"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-auth-gateway"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-auth-gateway-chevron"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-deployments"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-settings"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="nav-topology"]').exists()).toBe(true);

    expect(wrapper.find('[data-testid="test-content"]').exists()).toBe(true);
  });

  it('highlights the active route based on path prefix', async () => {
    mockRoute.value = { path: '/sites', fullPath: '/sites', name: 'sites', params: {}, query: {} };
    const wrapper = mount(DashboardLayout);

    const appNav = wrapper.find('[data-testid="nav-applications"]');
    expect(appNav.classes()).toContain('text-primary');

    const attacksNav = wrapper.find('[data-testid="nav-attacks"]');
    expect(attacksNav.classes()).not.toContain('text-primary');
  });

  it('displays crisp PNG brand logo, circular theme toggle, and no obsolete header clutter', () => {
    const wrapper = mount(DashboardLayout);

    expect(wrapper.find('[data-testid="tenant-selector"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="cluster-status"]').exists()).toBe(false);

    const brandLogo = wrapper.find('[data-testid="brand-logo"]');
    expect(brandLogo.exists()).toBe(true);
    const logoImg = brandLogo.find('img');
    expect(logoImg.exists()).toBe(true);
    expect(logoImg.attributes('src')).toMatch(/raiwall-logo\.png$/);

    expect(wrapper.find('[data-testid="version-badge"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain('WAF v2.8.4');
    expect(wrapper.text()).not.toContain('v1 Live');

    // Verify increased font size for navigation items
    const navItem = wrapper.find('[data-testid="nav-statistics"]');
    expect(navItem.classes()).toContain('text-[15px]');
    expect(navItem.classes()).toContain('font-medium');
  });

  it('navigates to route when navigation item is clicked', async () => {
    const wrapper = mount(DashboardLayout);

    await wrapper.find('[data-testid="nav-attacks"]').trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/attacks');
  });

  it('exposes a persistent Deployments entry and highlights the snapshots alias', async () => {
    const wrapper = mount(DashboardLayout);

    await wrapper.find('[data-testid="nav-deployments"]').trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/deployments');

    mockRoute.value = { path: '/snapshots', fullPath: '/snapshots', name: 'snapshots', params: {}, query: {} };
    const aliased = mount(DashboardLayout);
    expect(aliased.find('[data-testid="nav-deployments"]').classes()).toContain('text-primary');
  });

  it('renders circular theme toggle button and toggles theme on click', async () => {
    const wrapper = mount(DashboardLayout);

    const themeBtn = wrapper.find('[data-testid="theme-toggle-btn"]');
    expect(themeBtn.exists()).toBe(true);
    expect(themeBtn.classes()).toContain('rounded-full');
    expect(themeBtn.attributes('title')).toBeDefined();

    await themeBtn.trigger('click');
    expect(document.documentElement.classList.contains('light') || document.documentElement.classList.contains('dark')).toBe(true);
  });
});
