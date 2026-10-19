import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setActivePinia, createPinia } from 'pinia';
import { useConfigStore } from '../config';
import { api } from '@/api/client';

describe('config store', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
  });

  it('loads all entities into state', async () => {
    vi.spyOn(api, 'listSites').mockResolvedValue([
      {
        id: 'site-1',
        name: 'API Edge',
        hostnames: ['api.example.com'],
        mode: 'defense',
        upstreams: [{ dial: '10.0.0.1:8080', weight: 1 }],
        block_status_code: 403,
        offline_status_code: 503,
      },
    ]);
    vi.spyOn(api, 'listExceptions').mockResolvedValue([]);
    vi.spyOn(api, 'listACLs').mockResolvedValue([]);
    vi.spyOn(api, 'getPolicies').mockResolvedValue({
      tier1_rate: 100,
      tier1_burst: 200,
      tier2_threshold: 10,
      tier2_ban_seconds: 3600,
      tier3_threshold: 25,
      tier3_ban_seconds: 7200,
      bot_defense_mode: 'defense',
      pow_difficulty: 20000,
      honeypot_enabled: true,
      waiting_room_enabled: false,
      waiting_room_max_concurrent: 1000,
    });
    vi.spyOn(api, 'getDraftDiff').mockResolvedValue({
      has_changes: true,
      diffs: [
        {
          type: 'site',
          action: 'added',
          name: 'API Edge',
          details: 'New site added',
        },
      ],
    });
    vi.spyOn(api, 'getConfigHistory').mockResolvedValue([
      {
        version: 1,
        author: 'admin',
        description: 'Initial',
        applied_at: new Date().toISOString(),
        hash: 'abc',
      },
    ]);
    vi.spyOn(api, 'getClusterStatus').mockResolvedValue({
      mode: 'cluster',
      redis_connected: true,
      active_version: 1,
      channel: 'raiwall:cluster',
    });

    const store = useConfigStore();
    await store.loadAll();

    expect(store.sites.length).toBe(1);
    expect(store.sites[0].name).toBe('API Edge');
    expect(store.hasDraftChanges).toBe(true);
    expect(store.diffs.length).toBe(1);
    expect(store.activeVersion).toBe(1);
  });

  it('creates a site and updates draft diffs', async () => {
    vi.spyOn(api, 'createSite').mockResolvedValue({
      id: 'site-new',
      name: 'New Site',
      hostnames: ['new.example.com'],
      mode: 'audit',
      upstreams: [],
      block_status_code: 403,
      offline_status_code: 503,
    });
    vi.spyOn(api, 'getDraftDiff').mockResolvedValue({
      has_changes: true,
      diffs: [
        {
          type: 'site',
          action: 'added',
          name: 'New Site',
          details: 'Site created',
        },
      ],
    });

    const store = useConfigStore();
    const created = await store.createSite({ name: 'New Site' });

    expect(created.name).toBe('New Site');
    expect(store.sites.length).toBe(1);
    expect(store.hasDraftChanges).toBe(true);
  });
});
