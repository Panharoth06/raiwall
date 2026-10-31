import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import { ref } from 'vue';
import BreadcrumbNav from '../BreadcrumbNav.vue';
import { useConfigStore } from '@/stores/config';

const mockRoute = ref({
  path: '/statistics',
  fullPath: '/statistics',
  name: 'statistics',
  params: {} as Record<string, string>,
  query: {} as Record<string, string>,
});

const mockPush = vi.fn();

vi.mock('@/router', () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({
    push: mockPush,
  }),
}));

describe('BreadcrumbNav.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mockRoute.value = {
      path: '/statistics',
      fullPath: '/statistics',
      name: 'statistics',
      params: {},
      query: {},
    };
    mockPush.mockClear();
  });

  it('renders root breadcrumbs for Statistics overview', () => {
    const wrapper = mount(BreadcrumbNav);
    const breadcrumb = wrapper.find('[data-testid="navbar-breadcrumbs"]');
    expect(breadcrumb.exists()).toBe(true);

    const active = wrapper.find('[data-testid="breadcrumb-active"]');
    expect(active.exists()).toBe(true);
    expect(active.text()).toBe('Statistics');

    const links = wrapper.findAll('[data-testid="breadcrumb-link"]');
    expect(links.length).toBe(1);
    expect(links[0].text()).toContain('Dashboard');
  });

  it('renders multi-level breadcrumbs for site forwarding rules and navigates on click', async () => {
    const configStore = useConfigStore();
    configStore.sites = [
      {
        id: 'site-test-123',
        name: 'Api Production',
        hostnames: ['api.corp.internal'],
        mode: 'defense',
        ports: [],
        ssl_mode: 'none',
        routing_type: 'proxy',
        load_balancing: 'round_robin',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
    ];

    mockRoute.value = {
      path: '/sites/site-test-123/rules',
      fullPath: '/sites/site-test-123/rules',
      name: 'site-detail-rules',
      params: { id: 'site-test-123' },
      query: {},
    };

    const wrapper = mount(BreadcrumbNav);

    const active = wrapper.find('[data-testid="breadcrumb-active"]');
    expect(active.text()).toBe('Forwarding Rules');

    const links = wrapper.findAll('[data-testid="breadcrumb-link"]');
    expect(links.length).toBe(3);
    expect(links[0].text()).toContain('Dashboard');
    expect(links[1].text()).toContain('Applications');
    expect(links[2].text()).toContain('Api Production');

    // Click 'Applications' link to navigate back
    await links[1].trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/sites');

    // Click 'Api Production' link to navigate to site basic detail
    await links[2].trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/sites/site-test-123');
  });

  it('renders breadcrumbs for nested HTTP flood sections', async () => {
    mockRoute.value = {
      path: '/http-flood/waiting-room',
      fullPath: '/http-flood/waiting-room',
      name: 'http-flood-waiting-room',
      params: {},
      query: {},
    };

    const wrapper = mount(BreadcrumbNav);
    const active = wrapper.find('[data-testid="breadcrumb-active"]');
    expect(active.text()).toBe('Waiting Room');

    const links = wrapper.findAll('[data-testid="breadcrumb-link"]');
    expect(links.length).toBe(2);
    expect(links[1].text()).toContain('HTTP Flood');

    await links[1].trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/http-flood/limits');
  });

  it('renders breadcrumbs for Auth Gateway user management', async () => {
    mockRoute.value = {
      path: '/auth-gateway/users',
      fullPath: '/auth-gateway/users',
      name: 'auth-gateway-users',
      params: {},
      query: {},
    };

    const wrapper = mount(BreadcrumbNav);
    const active = wrapper.find('[data-testid="breadcrumb-active"]');
    expect(active.text()).toBe('User Management');

    const links = wrapper.findAll('[data-testid="breadcrumb-link"]');
    expect(links[1].text()).toContain('Auth Gateway');

    await links[1].trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/auth-gateway/logs');
  });

  it('renders breadcrumbs for Attacks forensic security logs when tab query is present', async () => {
    mockRoute.value = {
      path: '/attacks',
      fullPath: '/attacks?tab=logs',
      name: 'attacks',
      params: {},
      query: { tab: 'logs' },
    };

    const wrapper = mount(BreadcrumbNav);
    const active = wrapper.find('[data-testid="breadcrumb-active"]');
    expect(active.text()).toBe('Forensic Security Logs');

    const links = wrapper.findAll('[data-testid="breadcrumb-link"]');
    expect(links[1].text()).toContain('Attacks');

    await links[1].trigger('click');
    expect(mockPush).toHaveBeenCalledWith('/attacks');
  });

  it('renders breadcrumbs for incident radar and rule tester subtabs', async () => {
    mockRoute.value = {
      path: '/attacks',
      fullPath: '/attacks?view=incidents',
      name: 'attacks',
      params: {},
      query: { view: 'incidents' },
    };
    const wrapper1 = mount(BreadcrumbNav);
    expect(wrapper1.find('[data-testid="breadcrumb-active"]').text()).toBe('Incident Radar');

    mockRoute.value = {
      path: '/detection/tester',
      fullPath: '/detection/tester',
      name: 'detection-tester',
      params: {},
      query: {},
    };
    const wrapper2 = mount(BreadcrumbNav);
    expect(wrapper2.find('[data-testid="breadcrumb-active"]').text()).toBe('Rule Tester');
  });

  it('extracts site ID gracefully when route.params is not populated', async () => {
    mockRoute.value = {
      path: '/sites/site-orphan-8888',
      fullPath: '/sites/site-orphan-8888',
      name: 'site-detail',
      params: {},
      query: {},
    };
    const wrapper = mount(BreadcrumbNav);
    const active = wrapper.find('[data-testid="breadcrumb-active"]');
    expect(active.text()).toContain('App site-orp');
  });
});
