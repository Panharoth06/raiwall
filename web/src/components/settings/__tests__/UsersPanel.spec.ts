import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils';
import { nextTick } from 'vue';
import UsersPanel from '../UsersPanel.vue';
import { api, type AdminUser } from '@/api/client';

vi.mock('@/api/client', () => ({
  api: {
    listAdminUsers: vi.fn(),
    createAdminUser: vi.fn(),
    updateAdminUser: vi.fn(),
    resetAdminUserPassword: vi.fn(),
    revokeAdminUserSessions: vi.fn(),
    deactivateAdminUser: vi.fn(),
  },
}));

const mocked = vi.mocked(api);

const operator = (overrides: Partial<AdminUser> = {}): AdminUser => ({
  id: 'u-1',
  username: 'alice',
  role: 'admin',
  is_active: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  ...overrides,
});

const findButton = (label: string): HTMLButtonElement | undefined =>
  Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.includes(label));

describe('UsersPanel.vue', () => {
  let wrapper: VueWrapper | undefined;

  beforeEach(() => {
    document.body.innerHTML = '';
    vi.clearAllMocks();
    vi.mocked(mocked.listAdminUsers).mockResolvedValue([]);
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = undefined;
    document.body.innerHTML = '';
  });

  it('renders operators and flags inactive accounts', async () => {
    vi.mocked(mocked.listAdminUsers).mockResolvedValue([
      operator(),
      operator({ id: 'u-2', username: 'bill', role: 'viewer', is_active: false }),
    ]);
    wrapper = mount(UsersPanel, { attachTo: document.body });
    await flushPromises();

    const text = wrapper.text();
    expect(text).toContain('alice');
    expect(text).toContain('bill');
    expect(text).toContain('Inactive');
    expect(text).toContain('viewer');
  });

  it('shows the empty state and opens the create dialog', async () => {
    wrapper = mount(UsersPanel, { attachTo: document.body });
    await flushPromises();

    expect(wrapper.text()).toContain('No operators yet');
    const add = findButton('Add operator');
    expect(add).toBeTruthy();
    add?.click();
    await nextTick();

    expect(document.getElementById('operator-username')).toBeTruthy();
  });

  it('creates an operator and shows the generated password once', async () => {
    vi.mocked(mocked.createAdminUser).mockResolvedValue({
      user: operator({ id: 'u-3', username: 'carol', role: 'viewer' }),
      password: 'generated-secret',
    });
    vi.mocked(mocked.listAdminUsers)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([operator({ id: 'u-3', username: 'carol', role: 'viewer' })]);

    wrapper = mount(UsersPanel, { attachTo: document.body });
    await flushPromises();

    findButton('Add operator')?.click();
    await nextTick();

    const input = document.getElementById('operator-username') as HTMLInputElement;
    input.value = 'carol';
    input.dispatchEvent(new Event('input'));
    await nextTick();

    findButton('Create operator')?.click();
    await flushPromises();

    expect(mocked.createAdminUser).toHaveBeenCalledWith({
      username: 'carol',
      password: undefined,
      role: 'viewer',
    });
    expect(document.body.textContent).toContain('generated-secret');
    expect(document.body.textContent).toContain('One-time credentials');
  });

  it('surfaces load errors with a retry', async () => {
    vi.mocked(mocked.listAdminUsers)
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce([operator()]);

    wrapper = mount(UsersPanel, { attachTo: document.body });
    await flushPromises();
    expect(wrapper.text()).toContain('boom');

    findButton('Retry')?.click();
    await flushPromises();
    expect(wrapper.text()).toContain('alice');
  });
});
