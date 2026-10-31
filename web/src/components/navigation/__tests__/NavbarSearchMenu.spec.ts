import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import NavbarSearchMenu from '../NavbarSearchMenu.vue';

const mockPush = vi.fn();

vi.mock('@/router', () => ({
  useRouter: () => ({
    push: mockPush,
  }),
}));

describe('NavbarSearchMenu.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mockPush.mockClear();
  });

  it('renders navbar search trigger with shortcut badge', () => {
    const wrapper = mount(NavbarSearchMenu);
    const trigger = wrapper.find('[data-testid="navbar-search-trigger"]');
    expect(trigger.exists()).toBe(true);
    expect(trigger.text()).toContain('Search routes, sites, actions...');
    expect(trigger.text()).toContain('K');
  });

  it('opens command palette dialog when trigger is clicked', async () => {
    const wrapper = mount(NavbarSearchMenu, {
      attachTo: document.body,
    });

    expect(document.body.querySelector('[data-testid="navbar-search-dialog"]')).toBeNull();

    await wrapper.find('[data-testid="navbar-search-trigger"]').trigger('click');

    const dialog = document.body.querySelector('[data-testid="navbar-search-dialog"]');
    expect(dialog).not.toBeNull();

    const input = document.body.querySelector<HTMLInputElement>('[data-testid="navbar-search-input"]');
    expect(input).not.toBeNull();

    // Close using close button
    const closeBtn = document.body.querySelector<HTMLButtonElement>('[data-testid="navbar-search-close"]');
    closeBtn?.click();
    await wrapper.vm.$nextTick();

    expect(document.body.querySelector('[data-testid="navbar-search-dialog"]')).toBeNull();
    wrapper.unmount();
  });

  it('filters results and navigates when item is clicked', async () => {
    const wrapper = mount(NavbarSearchMenu, {
      attachTo: document.body,
    });

    await wrapper.find('[data-testid="navbar-search-trigger"]').trigger('click');

    const input = document.body.querySelector<HTMLInputElement>('[data-testid="navbar-search-input"]')!;
    input.value = 'Anti-Bot';
    input.dispatchEvent(new Event('input'));
    await wrapper.vm.$nextTick();

    const result = document.body.querySelector<HTMLButtonElement>('[data-testid="search-result-nav-bot"]')!;
    expect(result).not.toBeNull();
    expect(result.textContent).toContain('Anti-Bot Mitigation');

    result.click();
    await wrapper.vm.$nextTick();

    expect(mockPush).toHaveBeenCalledWith('/anti-bot');
    expect(document.body.querySelector('[data-testid="navbar-search-dialog"]')).toBeNull();
    wrapper.unmount();
  });

  it('navigates with Enter key', async () => {
    const wrapper = mount(NavbarSearchMenu, {
      attachTo: document.body,
    });

    await wrapper.find('[data-testid="navbar-search-trigger"]').trigger('click');

    const input = document.body.querySelector<HTMLInputElement>('[data-testid="navbar-search-input"]')!;
    input.value = 'Waiting Room';
    input.dispatchEvent(new Event('input'));
    await wrapper.vm.$nextTick();

    // Trigger Enter keydown
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    await wrapper.vm.$nextTick();

    expect(mockPush).toHaveBeenCalledWith('/http-flood/waiting-room');
    wrapper.unmount();
  });

  it('opens search palette when forward slash key is pressed', async () => {
    const wrapper = mount(NavbarSearchMenu, {
      attachTo: document.body,
    });

    expect(document.body.querySelector('[data-testid="navbar-search-dialog"]')).toBeNull();

    window.dispatchEvent(new KeyboardEvent('keydown', { key: '/' }));
    await wrapper.vm.$nextTick();

    const dialog = document.body.querySelector('[data-testid="navbar-search-dialog"]');
    expect(dialog).not.toBeNull();

    const input = document.body.querySelector<HTMLInputElement>('[data-testid="navbar-search-input"]')!;
    input.value = 'Exceptions';
    input.dispatchEvent(new Event('input'));
    await wrapper.vm.$nextTick();

    const result = document.body.querySelector<HTMLButtonElement>('[data-testid="search-result-nav-exceptions"]')!;
    expect(result).not.toBeNull();
    expect(result.textContent).toContain('Exceptions Gate');

    result.click();
    await wrapper.vm.$nextTick();
    expect(mockPush).toHaveBeenCalledWith('/detection/exceptions');

    wrapper.unmount();
  });

  it('allows ArrowDown and ArrowUp keys to navigate and scroll through search results', async () => {
    const wrapper = mount(NavbarSearchMenu, {
      attachTo: document.body,
    });

    await wrapper.find('[data-testid="navbar-search-trigger"]').trigger('click');
    await wrapper.vm.$nextTick();

    const options = document.body.querySelectorAll<HTMLButtonElement>('[role="option"]');
    expect(options.length).toBeGreaterThan(1);

    // Initial state: first item selected
    expect(options[0].getAttribute('aria-selected')).toBe('true');

    // Press ArrowDown
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    await wrapper.vm.$nextTick();

    expect(options[0].getAttribute('aria-selected')).toBe('false');
    expect(options[1].getAttribute('aria-selected')).toBe('true');

    // Press ArrowUp
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
    await wrapper.vm.$nextTick();

    expect(options[0].getAttribute('aria-selected')).toBe('true');

    wrapper.unmount();
  });
});
