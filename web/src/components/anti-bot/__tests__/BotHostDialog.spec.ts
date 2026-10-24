import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, type VueWrapper } from '@vue/test-utils';
import { nextTick } from 'vue';
import BotHostDialog from '../BotHostDialog.vue';
import type { BotConfig } from '@/api/bot';

const override: BotConfig = {
  id: 'bot-app',
  host: 'app.example.com',
  pow_enabled: true,
  pow_difficulty: 80000,
  trap_urls: ['/trap/app', '/admin'],
  is_active: false,
};

describe('BotHostDialog.vue', () => {
  let wrapper: VueWrapper | undefined;

  beforeEach(() => {
    document.body.innerHTML = '';
    vi.restoreAllMocks();
  });

  afterEach(() => {
    wrapper?.unmount();
    document.body.innerHTML = '';
  });

  const mountDialog = (config: BotConfig | null = null) => {
    wrapper = mount(BotHostDialog, {
      props: { open: true, config, suggestions: ['app.example.com'] },
      attachTo: document.body,
    });
    return wrapper;
  };

  const input = (testId: string) =>
    document.body.querySelector(`[data-testid="${testId}"]`) as HTMLElement | null;

  it('prefills an existing override and emits a normalized draft', async () => {
    mountDialog(override);
    await nextTick();
    await nextTick();

    const hostInput = input('bot-host-input') as HTMLInputElement;
    expect(hostInput.value).toBe('app.example.com');
    expect((input('bot-traps-input') as HTMLTextAreaElement).value).toContain('/trap/app');

    hostInput.value = '  api.example.com  ';
    hostInput.dispatchEvent(new Event('input'));

    const traps = input('bot-traps-input') as HTMLTextAreaElement;
    traps.value = '/trap/one\n  /trap/two  \n';
    traps.dispatchEvent(new Event('input'));

    (input('bot-save-host') as HTMLButtonElement).click();
    await nextTick();

    const emitted = wrapper!.emitted('save');
    expect(emitted).toBeTruthy();
    expect(emitted![0][0]).toEqual({
      host: 'api.example.com',
      pow_enabled: true,
      pow_difficulty: 80000,
      trap_urls: ['/trap/one', '/trap/two'],
      is_active: false,
    });
  });

  it('rejects a missing host and an invalid difficulty', async () => {
    mountDialog(null);
    await nextTick();
    await nextTick();

    (input('bot-save-host') as HTMLButtonElement).click();
    await nextTick();
    expect(document.body.textContent).toContain('Host is required');
    expect(wrapper!.emitted('save')).toBeFalsy();

    const hostInput = input('bot-host-input') as HTMLInputElement;
    hostInput.value = 'api.example.com';
    hostInput.dispatchEvent(new Event('input'));

    const difficulty = input('bot-difficulty-input')!.querySelector('input') as HTMLInputElement;
    difficulty.value = '500';
    difficulty.dispatchEvent(new Event('input'));
    await nextTick();

    (input('bot-save-host') as HTMLButtonElement).click();
    await nextTick();
    expect(document.body.textContent).toContain('Difficulty must be between');
    expect(wrapper!.emitted('save')).toBeFalsy();
  });

  it('rejects trap URLs that do not start with a slash', async () => {
    mountDialog(null);
    await nextTick();
    await nextTick();

    const hostInput = input('bot-host-input') as HTMLInputElement;
    hostInput.value = 'api.example.com';
    hostInput.dispatchEvent(new Event('input'));

    const traps = input('bot-traps-input') as HTMLTextAreaElement;
    traps.value = 'admin/login.php';
    traps.dispatchEvent(new Event('input'));

    (input('bot-save-host') as HTMLButtonElement).click();
    await nextTick();

    expect(document.body.textContent).toContain('must start with /');
    expect(wrapper!.emitted('save')).toBeFalsy();
  });
});
