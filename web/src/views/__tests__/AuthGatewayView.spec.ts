import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import AuthGatewayView from '../AuthGatewayView.vue';
import UserDirectoryTable from '@/components/UserDirectoryTable.vue';
import IdPConfigModal from '@/components/identity/IdPConfigModal.vue';
import SsoPortalPanel from '@/components/identity/SsoPortalPanel.vue';
import { router } from '@/router';
import { identityApi, type IdentityUser, type IdentityUserEnrollment, type IdentityAuthEvent } from '@/api/identity';
import { api, type Site } from '@/api/client';

vi.mock('@/api/identity', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@/api/identity')>();
  return {
    ...mod,
    identityApi: Object.fromEntries(
      [
        'listUsers', 'createUser', 'updateUser', 'deleteUser', 'resetUserPassword',
        'resetUserTOTP', 'listProviders', 'createProvider', 'updateProvider',
        'deleteProvider', 'listAuthEvents',
      ].map((k) => [k, vi.fn()]),
    ),
  };
});

vi.mock('@/api/client', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@/api/client')>();
  return { ...mod, api: { ...mod.api, listSites: vi.fn(), updateSite: vi.fn() } };
});

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const mockUser: IdentityUser = {
  id: 'idusr-1',
  username: 'walter',
  email: 'walter@corp.example',
  display_name: 'Walter Ops',
  totp_enrolled: false,
  app_ids: [],
  enabled: true,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const mockEvents: IdentityAuthEvent[] = [
  {
    created_at: new Date(Date.now() - 60_000).toISOString(),
    username: 'walter',
    app_id: 'app-1',
    host: 'app.example.com',
    method: 'POST',
    result: 'success',
    client_ip: '198.51.100.7',
    country: 'US',
    detail: 'clearance issued',
  },
  {
    created_at: new Date(Date.now() - 120_000).toISOString(),
    username: 'ghost',
    app_id: 'app-1',
    host: 'app.example.com',
    method: 'POST',
    result: 'unknown_user',
    client_ip: '203.0.113.9',
    country: 'DE',
    detail: 'directory lookup miss',
  },
];

const mockSite: Site = {
  id: 'site-1',
  name: 'Portal',
  hostnames: ['app.example.com'],
  mode: 'defense',
  upstreams: [{ dial: '10.0.0.5:8080', weight: 1 }],
  block_status_code: 403,
  offline_status_code: 503,
  auth_enabled: false,
  auth_bypass_paths: [],
};

beforeEach(async () => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  document.body.innerHTML = '';
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;

  vi.mocked(identityApi.listAuthEvents).mockResolvedValue(mockEvents);
  vi.mocked(identityApi.listUsers).mockResolvedValue([mockUser]);
  const enrolled = (user: IdentityUser, secret: string): IdentityUserEnrollment => ({
    ...user,
    totp_enrolled: true,
    totp_secret: secret,
    totp_provisioning_uri: `otpauth://totp/Raiwall:${user.id}?secret=${secret}`,
  });
  vi.mocked(identityApi.createUser).mockImplementation(async ({ username }) =>
    enrolled({ ...mockUser, username, id: 'idusr-new' }, 'JBSWY3DPEHPK3PXP'));
  vi.mocked(identityApi.resetUserTOTP).mockResolvedValue(enrolled(mockUser, 'JBSWY3DPEHPK3PXP'));
  vi.mocked(identityApi.listProviders).mockResolvedValue([]);
  vi.mocked(api.listSites).mockResolvedValue([mockSite]);
  vi.mocked(api.updateSite).mockResolvedValue({ ...mockSite, auth_enabled: true });
});

describe('AuthGatewayView.vue', () => {
  it('renders the Authentication Logs panel by default', async () => {
    await router.navigate('/auth-gateway');
    const wrapper = mount(AuthGatewayView);
    await flushPromises();

    expect(identityApi.listAuthEvents).toHaveBeenCalled();
    expect(wrapper.find('[data-testid="auth-panel-logs"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('walter');
    expect(wrapper.text()).toContain('unknown_user');
  });

  it('swaps panels on the sub-routes', async () => {
    await router.navigate('/auth-gateway/users');
    let wrapper = mount(AuthGatewayView);
    await flushPromises();
    expect(wrapper.find('[data-testid="auth-panel-users"]').exists()).toBe(true);
    wrapper.unmount();

    await router.navigate('/auth-gateway/sso');
    wrapper = mount(AuthGatewayView);
    await flushPromises();
    expect(wrapper.find('[data-testid="auth-panel-sso"]').exists()).toBe(true);
    wrapper.unmount();

    await router.navigate('/auth-gateway/idp');
    wrapper = mount(AuthGatewayView);
    await flushPromises();
    expect(wrapper.find('[data-testid="auth-panel-idp"]').exists()).toBe(true);
    wrapper.unmount();
  });
});

describe('UserDirectoryTable.vue (user creation + TOTP reset)', () => {
  const bodyText = () => document.body.textContent || '';

  const clickUserDialogSave = async () => {
    const save = document.body.querySelector('[data-testid="user-dialog-save"]') as HTMLButtonElement;
    expect(save).toBeTruthy();
    save.click();
    await nextTick();
    await nextTick();
  };

  it('creates a directory user through the add dialog', async () => {
    const wrapper = mount(UserDirectoryTable);
    await flushPromises();

    expect(wrapper.find('[data-testid="user-row-0"]').exists()).toBe(true);
    await wrapper.find('[data-testid="user-add"]').trigger('click');
    await nextTick();
    await nextTick();

    setDialogInput('user-dialog-username', 'walter-new');
    setDialogInput('user-dialog-password', 'Sup3rSecret!');
    await clickUserDialogSave();
    await flushPromises();

    expect(identityApi.createUser).toHaveBeenCalledWith(
      expect.objectContaining({ username: 'walter-new', app_ids: [] }),
    );
  });

  it('rejects a create without the minimum password length client-side', async () => {
    const wrapper = mount(UserDirectoryTable);
    await flushPromises();
    await wrapper.find('[data-testid="user-add"]').trigger('click');
    await nextTick();
    await nextTick();

    setDialogInput('user-dialog-username', 'walter-short');
    setDialogInput('user-dialog-password', 'short');
    await clickUserDialogSave();

    expect(identityApi.createUser).not.toHaveBeenCalled();
    expect(bodyText()).toContain('Password must be at least 8 characters.');
    wrapper.unmount();
  });

  it('enrolls 2FA via the reset action and shows the one-time secret', async () => {
    const wrapper = mount(UserDirectoryTable);
    await flushPromises();

    await wrapper.find('[data-testid="user-totp-reset-0"]').trigger('click');
    await flushPromises();

    expect(identityApi.resetUserTOTP).toHaveBeenCalledWith('idusr-1', true);
    const panel = wrapper.find('[data-testid="totp-enrollment-panel"]');
    expect(panel.exists()).toBe(true);
    expect(wrapper.text()).toContain('JBSWY3DPEHPK3PXP');
    wrapper.unmount();
  });
});

describe('IdPConfigModal.vue (connector validation)', () => {
  const bodyText = () => document.body.textContent || '';

  const mountModal = () => {
    const wrapper = mount(IdPConfigModal, {
      props: { open: true, provider: null },
      attachTo: document.body,
    });
    return wrapper;
  };

  const setModalField = (key: string, value: string) => {
    const input = document.body.querySelector(`[data-testid="idp-field-${key}"] input`) as HTMLInputElement;
    expect(input).toBeTruthy();
    input.value = value;
    input.dispatchEvent(new Event('input'));
  };

  const clickSave = async () => {
    const save = document.body.querySelector('[data-testid="idp-dialog-save"]') as HTMLButtonElement;
    expect(save).toBeTruthy();
    save.click();
    await nextTick();
    await nextTick();
  };

  it('shows the backend-mirrored validation errors for an empty OIDC form', async () => {
    const wrapper = mountModal();
    await nextTick();
    await clickSave();

    expect(bodyText()).toContain('Provider name is required.');
    expect(identityApi.createProvider).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it('rejects an ldap:// scheme-less LDAP host before save', async () => {
    const wrapper = mountModal();
    await nextTick();
    await (wrapper.vm as any).switchType('ldap');
    await nextTick();
    await (wrapper.vm as any).setName('Corp AD');

    setModalField('host_url', 'dc01.corp.example:389');
    setModalField('user_base_dn', 'ou=people,dc=corp,dc=example');
    setModalField('user_filter', '(uid=%s)');
    await clickSave();

    expect(bodyText()).toContain('ldap:// or ldaps://');
    wrapper.unmount();
  });

  it('accepts a complete GitHub OAuth2 configuration', async () => {
    const wrapper = mountModal();
    await nextTick();
    await (wrapper.vm as any).switchType('github');
    await nextTick();
    await (wrapper.vm as any).setName('GitHub SSO');

    setModalField('client_id', 'Iv1.abc');
    setModalField('client_secret', 'shhh');
    await clickSave();

    expect(wrapper.emitted('save')?.at(-1)).toEqual([
      {
        type: 'github',
        name: 'GitHub SSO',
        config: { client_id: 'Iv1.abc', client_secret: 'shhh' },
      },
    ]);
    expect(bodyText()).not.toContain('is required.');
    wrapper.unmount();
  });
});

describe('SsoPortalPanel.vue (per-site portal enforcement)', () => {
  it('applies the gate toggle and bypass paths to the site', async () => {
    const wrapper = mount(SsoPortalPanel);
    await flushPromises();

    expect(wrapper.find('[data-testid="sso-row-0"]').exists()).toBe(true);
    await wrapper.find('[data-testid="sso-toggle-0"]').trigger('click');
    await nextTick();

    const bypass = wrapper.find('input[data-testid="sso-bypass-0"]');
    bypass.element.value = '/health, /assets';
    await bypass.trigger('input');

    await wrapper.find('[data-testid="sso-apply-0"]').trigger('click');
    await flushPromises();

    expect(api.updateSite).toHaveBeenCalledWith('site-1', {
      auth_enabled: true,
      auth_bypass_paths: ['/health', '/assets'],
    });
    wrapper.unmount();
  });
});

// --- helpers ---------------------------------------------------------------

function setDialogInput(testId: string, value: string) {
  const input = document.body.querySelector(`[data-testid="${testId}"] input`) as HTMLInputElement;
  expect(input).toBeTruthy();
  input.value = value;
  input.dispatchEvent(new Event('input'));
}
