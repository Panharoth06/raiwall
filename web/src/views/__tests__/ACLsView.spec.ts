import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import ACLsView from '../ACLsView.vue';
import { useConfigStore } from '@/stores/config';
import type { ACLRule } from '@/api/client';

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;
});

describe('ACLsView.vue (SafeLine Allow & Deny Flow)', () => {
  const sampleRules: ACLRule[] = [
    {
      id: 'acl-001',
      name: 'Allow Office Subnet',
      expression: 'in_cidr(client_ip, "192.168.1.0/24")',
      action: 'allow',
      priority: 10,
      enabled: true,
      created_at: '2026-07-24T17:26:21Z',
    },
    {
      id: 'acl-002',
      name: 'Block Scanner User-Agents',
      expression: 'str_contains(user_agent, "sqlmap")',
      action: 'block',
      priority: 20,
      enabled: true,
      created_at: '2026-07-27T17:07:28Z',
    },
  ];

  it('renders header and Whitelist/Blacklist tabs with counts', () => {
    const store = useConfigStore();
    store.acls = [...sampleRules];

    const wrapper = mount(ACLsView);

    expect(wrapper.text()).toContain('Allow & Deny Rules');
    expect(wrapper.text()).toContain('WHITELIST');
    expect(wrapper.text()).toContain('(1)');
    expect(wrapper.text()).toContain('BLACKLIST');
  });

  it('filters rules by Whitelist by default and switches to Blacklist on click', async () => {
    const store = useConfigStore();
    store.acls = [...sampleRules];

    const wrapper = mount(ACLsView);

    // Whitelist is active by default
    expect(wrapper.text()).toContain('Allow Office Subnet');
    expect(wrapper.text()).not.toContain('Block Scanner User-Agents');

    // Click Blacklist tab
    const buttons = wrapper.findAll('button');
    const blacklistBtn = buttons.find((b) => b.text().includes('BLACKLIST'));
    expect(blacklistBtn).toBeDefined();

    await blacklistBtn!.trigger('click');
    await nextTick();

    // Now Blacklist is visible
    expect(wrapper.text()).toContain('Block Scanner User-Agents');
    expect(wrapper.text()).not.toContain('Allow Office Subnet');
  });

  it('opens modal when clicking ADD RULES button', async () => {
    const store = useConfigStore();
    store.acls = [];

    const wrapper = mount(ACLsView, {
      attachTo: document.body,
    });

    const addBtn = wrapper.findAll('button').find((b) => b.text().includes('ADD RULES'));
    expect(addBtn).toBeDefined();

    await addBtn!.trigger('click');
    await nextTick();
    await nextTick();

    // Check if dialog content appears in document body
    expect(document.body.textContent).toContain('Add rules');
    expect(document.body.textContent).toContain('Match Target');
    wrapper.unmount();
  });

  it('calls updateACL when toggling rule status switch', async () => {
    const store = useConfigStore();
    store.acls = [...sampleRules];
    const updateSpy = vi.spyOn(store, 'updateACL').mockResolvedValue(sampleRules[0]);

    const wrapper = mount(ACLsView);

    const switchBtn = wrapper.find('button[role="switch"]');
    expect(switchBtn.exists()).toBe(true);

    await switchBtn.trigger('click');
    await nextTick();

    expect(updateSpy).toHaveBeenCalledWith('acl-001', { enabled: false, is_active: false });
  });

  it('renders Continue Detect badge when continue_inspection is true', () => {
    const store = useConfigStore();
    store.acls = [
      {
        ...sampleRules[0],
        continue_inspection: true,
      },
    ];

    const wrapper = mount(ACLsView);
    expect(wrapper.text()).toContain('Continue Detect');
  });

  it('shows empty state when no rules exist for a tab', () => {
    const store = useConfigStore();
    store.acls = [];

    const wrapper = mount(ACLsView);

    expect(wrapper.text()).toContain('No Whitelist Rules Configured');
    expect(wrapper.text()).toContain('Add First Rule');
  });
});
