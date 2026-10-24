import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, type VueWrapper } from '@vue/test-utils';
import { nextTick } from 'vue';
import BotProtectDialog from '../BotProtectDialog.vue';
import type { BotConfig } from '@/api/bot';
import type { BotPolicyTarget } from '@/composables/useAntiBot';

const appTarget: BotPolicyTarget = {
  name: 'Checkout',
  hostnames: ['app.example.com', 'edge.example.com'],
};

const globalTarget: BotPolicyTarget = {
  name: 'Global default',
  hostnames: [],
  global: true,
};

const appConfig: BotConfig = {
  id: 'bot-app',
  host: 'app.example.com',
  pow_enabled: true,
  pow_difficulty: 80000,
  trap_urls: ['/trap/app', '/admin'],
  is_active: true,
};

describe('BotProtectDialog.vue', () => {
  let wrapper: VueWrapper | undefined;

  beforeEach(() => {
    document.body.innerHTML = '';
    vi.restoreAllMocks();
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = undefined;
    document.body.innerHTML = '';
  });

  const mountDialog = (props: {
    target?: BotPolicyTarget;
    config?: BotConfig | null;
    inherited?: boolean;
    custom?: boolean;
  }) => {
    wrapper = mount(BotProtectDialog, {
      props: {
        open: true,
        target: props.target ?? appTarget,
        config: props.config ?? null,
        inherited: props.inherited ?? false,
        custom: props.custom ?? false,
      },
      attachTo: document.body,
    });
    return wrapper;
  };

  const bodyEl = (testId: string) =>
    document.body.querySelector(`[data-testid="${testId}"]`) as HTMLElement | null;

  it('prefills an application policy and emits a full replacement payload', async () => {
    mountDialog({ config: appConfig, custom: true });
    await nextTick();
    await nextTick();

    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('Checkout');
    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('app.example.com');
    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('80,000');
    expect((bodyEl('bot-traps-input') as HTMLTextAreaElement).value).toContain('/trap/app');

    ;(bodyEl('bot-challenge-toggle') as HTMLButtonElement).click();
    await nextTick();
    ;(bodyEl('bot-save-protect') as HTMLButtonElement).click();
    await nextTick();

    const emitted = wrapper!.emitted('save');
    expect(emitted).toBeTruthy();
    expect(emitted![0][0]).toEqual({
      pow_enabled: false,
      pow_difficulty: 80000,
      trap_urls: ['/trap/app', '/admin'],
      is_active: true,
    });
  });

  it('rejects trap URLs that do not start with a slash', async () => {
    mountDialog({ target: appTarget, inherited: true });
    await nextTick();
    await nextTick();

    ;(bodyEl('bot-trap-toggle') as HTMLButtonElement).click();
    await nextTick();

    const traps = bodyEl('bot-traps-input') as HTMLTextAreaElement;
    traps.value = 'admin/login.php';
    traps.dispatchEvent(new Event('input'));
    await nextTick();

    ;(bodyEl('bot-save-protect') as HTMLButtonElement).click();
    await nextTick();

    expect(bodyEl('bot-protect-dialog')?.textContent).toContain('must start with /');
    expect(wrapper!.emitted('save')).toBeFalsy();
  });

  it('explains inheritance without offering a reset for unconfigured applications', async () => {
    mountDialog({ target: appTarget, inherited: true, custom: false });
    await nextTick();
    await nextTick();

    expect(bodyEl('bot-inherited-note')?.textContent).toContain('inherits the global policy');
    expect(bodyEl('bot-reset-policy')).toBeNull();
  });

  it('offers a reset only for an application-scoped policy', async () => {
    mountDialog({ target: appTarget, config: appConfig, custom: true });
    await nextTick();
    await nextTick();

    expect(bodyEl('bot-reset-policy')).not.toBeNull();
    ;(bodyEl('bot-reset-policy') as HTMLButtonElement).click();

    expect(wrapper!.emitted('reset')).toBeTruthy();
  });

  it('labels the wildcard scope and hides reset for the global default', async () => {
    mountDialog({ target: globalTarget, config: appConfig });
    await nextTick();
    await nextTick();

    expect(bodyEl('bot-protect-dialog')?.textContent).toContain(
      'All hosts without an application policy'
    );
    expect(bodyEl('bot-reset-policy')).toBeNull();
  });
});
