import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { ref } from 'vue';
import AttacksView from '../AttacksView.vue';

const mockRoute = ref({
  path: '/attacks',
  fullPath: '/attacks',
  name: 'attacks',
  params: {},
  query: {} as Record<string, string>,
});
const mockPush = vi.fn();

vi.mock('@/router', () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({
    push: mockPush,
  }),
}));

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  mockRoute.value = {
    path: '/attacks',
    fullPath: '/attacks',
    name: 'attacks',
    params: {},
    query: {},
  };
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;
});

describe('AttacksView.vue', () => {
  it('renders Tabs with 3 options: Events, Incidents and Logs, defaulting to Events', () => {
    const wrapper = mount(AttacksView, {
      global: {
        stubs: {
          LiveInspector: { template: '<div data-testid="live-inspector-stub">Live Inspector</div>' },
          LogsViewer: { template: '<div data-testid="logs-viewer-stub">Logs Viewer</div>' },
        },
      },
    });

    const tabItems = wrapper.findAll('[data-testid^="tab-"]').filter((el) => el.attributes('role') === 'tab');
    expect(tabItems.length).toBe(3);
    expect(tabItems[0].text()).toContain('Events');
    expect(tabItems[1].text()).toContain('Incidents');
    expect(tabItems[2].text()).toContain('Logs');

    expect(wrapper.find('[data-testid="live-inspector-stub"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="logs-viewer-stub"]').exists()).toBe(false);
  });

  it('switches to Logs view when clicking the Logs tab', async () => {
    const wrapper = mount(AttacksView, {
      global: {
        stubs: {
          LiveInspector: { template: '<div data-testid="live-inspector-stub">Live Inspector</div>' },
          LogsViewer: { template: '<div data-testid="logs-viewer-stub">Logs Viewer</div>' },
        },
      },
    });

    await wrapper.find('[data-testid="tab-logs"]').trigger('click');

    expect(mockPush).toHaveBeenCalledWith('/attacks?tab=logs');
    expect(wrapper.find('[data-testid="logs-viewer-stub"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="live-inspector-stub"]').exists()).toBe(false);
  });

  it('switches to the Incidents tab without leaving the live inspector', async () => {
    const wrapper = mount(AttacksView, {
      global: {
        stubs: {
          LiveInspector: { template: '<div data-testid="live-inspector-stub">Live Inspector</div>' },
          LogsViewer: { template: '<div data-testid="logs-viewer-stub">Logs Viewer</div>' },
        },
      },
    });

    await wrapper.find('[data-testid="tab-incidents"]').trigger('click');

    expect(mockPush).toHaveBeenCalledWith('/attacks?tab=incidents');
    expect(wrapper.find('[data-testid="live-inspector-stub"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="logs-viewer-stub"]').exists()).toBe(false);
  });

  it('initializes with the Incidents tab for legacy ?view=incidents links', () => {
    mockRoute.value.query = { view: 'incidents' };

    const wrapper = mount(AttacksView, {
      global: {
        stubs: {
          LiveInspector: { template: '<div data-testid="live-inspector-stub">Live Inspector</div>' },
          LogsViewer: { template: '<div data-testid="logs-viewer-stub">Logs Viewer</div>' },
        },
      },
    });

    expect(wrapper.find('[data-testid="live-inspector-stub"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="tab-incidents"]').attributes('aria-selected')).toBe('true');
  });

  it('initializes with Logs tab when query parameter tab=logs is present', () => {
    mockRoute.value.query = { tab: 'logs' };

    const wrapper = mount(AttacksView, {
      global: {
        stubs: {
          LiveInspector: { template: '<div data-testid="live-inspector-stub">Live Inspector</div>' },
          LogsViewer: { template: '<div data-testid="logs-viewer-stub">Logs Viewer</div>' },
        },
      },
    });

    expect(wrapper.find('[data-testid="logs-viewer-stub"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="live-inspector-stub"]').exists()).toBe(false);
  });
});
