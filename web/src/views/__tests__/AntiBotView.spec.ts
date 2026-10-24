import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import AntiBotView from '../AntiBotView.vue';
import { api } from '@/api/client';
import { botApi, type BotConfig } from '@/api/bot';
import { useConfigStore } from '@/stores/config';
import type { ForensicEvent } from '@/types/telemetry';

const globalConfig: BotConfig = {
  id: 'bot-global',
  host: '*',
  pow_enabled: true,
  pow_difficulty: 50000,
  trap_urls: ['/.raiwall/trap/honeypot'],
  is_active: true,
};

const appAConfig: BotConfig = {
  id: 'bot-app-a',
  host: 'app-a.example.com',
  pow_enabled: true,
  pow_difficulty: 80000,
  trap_urls: ['/trap/app'],
  is_active: true,
};

const appBConfig: BotConfig = {
  id: 'bot-app-b',
  host: 'b1.example.com',
  pow_enabled: false,
  pow_difficulty: 20000,
  trap_urls: [],
  is_active: true,
};

const challengeEvent: ForensicEvent = {
  event_id: 'evt-1',
  timestamp: '2026-10-24T02:00:00Z',
  host: 'app-a.example.com',
  path: '/login',
  method: 'GET',
  client_ip: '203.0.113.9',
  ja4: 't13d1516h2_app',
  action: 'challenge',
  severity: 'medium',
  latency: 0.4,
  status_code: 468,
};

function mockActivity() {
  vi.spyOn(api, 'listEvents').mockImplementation(async (params) => {
    if (params?.action === 'challenge') {
      return { events: [challengeEvent], total: 3, limit: 100, offset: 0 };
    }
    if (params?.rule_id === 'honeypot_trap') {
      return { events: [], total: 2, limit: 1, offset: 0 };
    }
    return { events: [], total: 1, limit: 1, offset: 0 };
  });
}

describe('AntiBotView.vue', () => {
  let wrapper: VueWrapper | undefined;

  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
    document.body.innerHTML = '';

    const store = useConfigStore();
    store.sites = [
      {
        id: 'site-a',
        name: 'App A',
        hostnames: ['app-a.example.com'],
        mode: 'defense',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
      {
        id: 'site-b',
        name: 'App B',
        hostnames: ['b1.example.com', 'b2.example.com'],
        mode: 'defense',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
      {
        id: 'site-c',
        name: 'App C',
        hostnames: ['app-c.example.com'],
        mode: 'audit',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
    ];
    vi.spyOn(botApi, 'list').mockResolvedValue([globalConfig, appAConfig, appBConfig]);
    mockActivity();
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = undefined;
    document.body.innerHTML = '';
  });

  const mountView = async () => {
    wrapper = mount(AntiBotView, { attachTo: document.body });
    await flushPromises();
    return wrapper;
  };

  const bodyEl = (testId: string) =>
    document.body.querySelector(`[data-testid="${testId}"]`) as HTMLElement | null;

  it('lists applications with global inheritance and partial overrides', async () => {
    const view = await mountView();

    expect(view.text()).toContain('Anti-Bot Defense');
    expect(view.text()).toContain('Applications');
    expect(view.text()).toContain('Global default');
    expect(view.findAll('[data-testid="bot-app-row"]')).toHaveLength(3);
    expect(view.findAll('[data-testid="bot-global-row"]')).toHaveLength(1);

    const appARow = view
      .findAll('[data-testid="bot-app-row"]')
      .find((row) => row.text().includes('App A'));
    expect(appARow?.text()).toContain('app-a.example.com');
    expect(appARow?.text()).toContain('On');
    expect(appARow?.text()).toContain('80,000');

    const appBRow = view
      .findAll('[data-testid="bot-app-row"]')
      .find((row) => row.text().includes('App B'));
    expect(appBRow?.text()).toContain('Partial');
    expect(appBRow?.text()).toContain('1/2 hosts');

    const appCRow = view
      .findAll('[data-testid="bot-app-row"]')
      .find((row) => row.text().includes('App C'));
    expect(appCRow?.text()).toContain('Inherits global');

    expect(view.get('[data-testid="bot-metric-challenges"]').text()).toContain('3');
    expect(view.get('[data-testid="bot-metric-trap-hits"]').text()).toContain('2');
    expect(view.get('[data-testid="bot-metric-unique-ja4"]').text()).toContain('1');
    expect(view.get('[data-testid="bot-activity-list"]').text()).toContain('203.0.113.9');
  });

  it('opens BOT Protect scoped to the application and saves every hostname', async () => {
    const updateSpy = vi.spyOn(botApi, 'update').mockResolvedValue(appBConfig);
    const createSpy = vi.spyOn(botApi, 'create').mockResolvedValue(appBConfig);
    const view = await mountView();

    const appBRow = view
      .findAll('[data-testid="bot-app-row"]')
      .find((row) => row.text().includes('App B'));
    await appBRow!.get('[data-testid="bot-configure-app"]').trigger('click');
    await flushPromises();

    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('BOT Protect');
    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('App B');

    ;(bodyEl('bot-challenge-toggle') as HTMLButtonElement).click();
    await flushPromises();
    ;(bodyEl('bot-difficulty-preset-100000') as HTMLButtonElement).click();
    await flushPromises();
    ;(bodyEl('bot-save-protect') as HTMLButtonElement).click();
    await flushPromises();

    expect(updateSpy).toHaveBeenCalledWith(
      'bot-app-b',
      expect.objectContaining({
        host: 'b1.example.com',
        pow_enabled: true,
        pow_difficulty: 100000,
        trap_urls: [],
        is_active: true,
      })
    );
    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        host: 'b2.example.com',
        pow_enabled: true,
        pow_difficulty: 100000,
        trap_urls: [],
        is_active: true,
      })
    );
    expect(view.get('[data-testid="bot-notice"]').text()).toContain('BOT Protect saved for App B');
  });

  it('shows the inheritance notice for an unconfigured application', async () => {
    const view = await mountView();

    const appCRow = view
      .findAll('[data-testid="bot-app-row"]')
      .find((row) => row.text().includes('App C'));
    await appCRow!.get('[data-testid="bot-configure-app"]').trigger('click');
    await flushPromises();

    expect(bodyEl('bot-inherited-note')?.textContent).toContain('inherits the global policy');
    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('app-c.example.com');
  });

  it('removes an application override so the global policy applies again', async () => {
    const removeSpy = vi.spyOn(botApi, 'remove').mockResolvedValue({
      status: 'deleted',
      id: 'bot-app-a',
    });
    const view = await mountView();

    const appARow = view
      .findAll('[data-testid="bot-app-row"]')
      .find((row) => row.text().includes('App A'));
    await appARow!.get('[data-testid="bot-configure-app"]').trigger('click');
    await flushPromises();

    ;(bodyEl('bot-reset-policy') as HTMLButtonElement).click();
    await flushPromises();

    expect(removeSpy).toHaveBeenCalledWith('bot-app-a');
    expect(view.get('[data-testid="bot-notice"]').text()).toContain('override removed for App A');
  });

  it('renders an actionable error state when policies fail to load', async () => {
    vi.spyOn(botApi, 'list').mockRejectedValue(new Error('control plane unavailable'));
    const view = await mountView();

    const error = view.get('[data-testid="bot-app-error"]');
    expect(error.text()).toContain('Could not load bot policies');
    expect(error.text()).toContain('control plane unavailable');
    expect(error.text()).toContain('Retry');
  });
});
