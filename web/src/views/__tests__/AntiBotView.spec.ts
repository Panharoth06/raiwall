import { describe, it, expect, beforeEach, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import AntiBotView from '../AntiBotView.vue';
import { api, type PolicySettings } from '@/api/client';
import { botApi, type BotConfig } from '@/api/bot';
import { useConfigStore } from '@/stores/config';
import type { ForensicEvent } from '@/types/telemetry';

const policies: PolicySettings = {
  tier1_rate: 100,
  tier1_burst: 200,
  tier2_threshold: 10,
  tier2_ban_seconds: 3600,
  tier3_threshold: 25,
  tier3_ban_seconds: 7200,
  bot_defense_mode: 'defense',
  pow_difficulty: 50000,
  honeypot_enabled: true,
  waiting_room_enabled: false,
  waiting_room_max_concurrent: 1000,
  waiting_room_paths: [],
};

const globalConfig: BotConfig = {
  id: 'bot-global',
  host: '*',
  pow_enabled: true,
  pow_difficulty: 50000,
  trap_urls: ['/.raiwall/trap/honeypot'],
  is_active: true,
};

const hostOverride: BotConfig = {
  id: 'bot-app',
  host: 'app.example.com',
  pow_enabled: true,
  pow_difficulty: 80000,
  trap_urls: ['/trap/app'],
  is_active: true,
};

const challengeEvent: ForensicEvent = {
  event_id: 'evt-1',
  timestamp: '2026-10-24T02:00:00Z',
  host: 'app.example.com',
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
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
    const store = useConfigStore();
    store.policies = { ...policies };
    store.sites = [
      {
        id: 'site-1',
        name: 'App',
        hostnames: ['app.example.com'],
        mode: 'defense',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
    ];
    vi.spyOn(botApi, 'list').mockResolvedValue([globalConfig, hostOverride]);
    mockActivity();
  });

  it('separates global policy from per-host overrides and shows challenge activity', async () => {
    const wrapper = mount(AntiBotView);
    await flushPromises();

    expect(wrapper.text()).toContain('Anti-Bot Defense');
    expect(wrapper.text()).toContain('Challenge Policy');
    expect(wrapper.text()).toContain('Per-Host Overrides');

    // The wildcard policy is edited above, never listed as a host override.
    expect(wrapper.findAll('[data-testid="bot-host-row"]')).toHaveLength(1);
    expect(wrapper.text()).toContain('app.example.com');
    expect(wrapper.text()).toContain('80,000');

    expect(wrapper.get('[data-testid="bot-metric-challenges"]').text()).toContain('3');
    expect(wrapper.get('[data-testid="bot-metric-trap-hits"]').text()).toContain('2');
    expect(wrapper.get('[data-testid="bot-metric-unique-ja4"]').text()).toContain('1');
    expect(wrapper.get('[data-testid="bot-activity-list"]').text()).toContain('203.0.113.9');
  });

  it('stages fingerprint-only mode without altering rate-limit fields', async () => {
    const updateSpy = vi.spyOn(api, 'updatePolicies').mockResolvedValue({ ...policies });
    const wrapper = mount(AntiBotView);
    await flushPromises();

    await wrapper.get('[data-testid="pow-disabled"]').trigger('click');
    await wrapper.get('[data-testid="save-bot-policy"]').trigger('click');
    await flushPromises();

    expect(updateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        bot_defense_mode: 'audit',
        pow_difficulty: 50000,
        honeypot_enabled: true,
        tier1_rate: 100,
        tier2_ban_seconds: 3600,
      })
    );
    expect(wrapper.get('[data-testid="bot-notice"]').text()).toContain('staged to the config draft');
  });

  it('persists a toggle with the full record so host overrides are not wiped', async () => {
    const updateSpy = vi.spyOn(botApi, 'update').mockResolvedValue(hostOverride);
    const wrapper = mount(AntiBotView);
    await flushPromises();

    await wrapper.get('[data-testid="bot-toggle-host"]').trigger('click');
    await flushPromises();

    expect(updateSpy).toHaveBeenCalledWith('bot-app', {
      host: 'app.example.com',
      pow_enabled: true,
      pow_difficulty: 80000,
      trap_urls: ['/trap/app'],
      is_active: false,
    });
  });

  it('renders an actionable error state when overrides fail to load', async () => {
    vi.spyOn(botApi, 'list').mockRejectedValue(new Error('control plane unavailable'));
    const wrapper = mount(AntiBotView);
    await flushPromises();

    const error = wrapper.get('[data-testid="bot-host-error"]');
    expect(error.text()).toContain('Could not load per-host overrides');
    expect(error.text()).toContain('control plane unavailable');
    expect(error.text()).toContain('Retry');
  });

  it('shows an empty state when only the wildcard policy exists', async () => {
    vi.spyOn(botApi, 'list').mockResolvedValue([globalConfig]);
    const wrapper = mount(AntiBotView);
    await flushPromises();

    expect(wrapper.get('[data-testid="bot-host-empty"]').text()).toContain(
      'No per-host overrides'
    );
  });
});
