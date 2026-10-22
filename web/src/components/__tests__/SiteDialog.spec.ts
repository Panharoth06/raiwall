import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { nextTick } from 'vue';
import SiteDialog from '../SiteDialog.vue';
import type { Site } from '@/api/client';

describe('SiteDialog.vue (SafeLine Application Flow)', () => {
  let wrapper: any;

  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    if (wrapper) {
      wrapper.unmount();
    }
    document.body.innerHTML = '';
  });

  it('renders with pre-populated "*" domain and ports 80 (HTTP) + 443 (HTTPS)', async () => {
    wrapper = mount(SiteDialog, {
      props: {
        open: true,
        site: null,
      },
      attachTo: document.body,
    });
    await nextTick();
    await nextTick();

    const bodyText = document.body.textContent || '';
    expect(bodyText).toContain('Add Application');
    expect(bodyText).toContain('Domain');
    expect(bodyText).toContain('*');
    expect(bodyText).toContain('Port');
    expect(bodyText).toContain('HTTP');
    expect(bodyText).toContain('HTTPS');
    expect(bodyText).toContain('Reverse Proxy');
    expect(bodyText).toContain('Upstream');
    expect(bodyText).toContain('SUBMIT');
    expect(bodyText).toContain('CANCEL');
  });

  it('allows adding and removing domain tags', async () => {
    wrapper = mount(SiteDialog, {
      props: {
        open: true,
        site: null,
      },
      attachTo: document.body,
    });
    await nextTick();
    await nextTick();

    const domainInput = document.body.querySelector('input[placeholder*="www.example.com"]') as HTMLInputElement;
    expect(domainInput).toBeTruthy();

    domainInput.value = 'api.example.com';
    domainInput.dispatchEvent(new Event('input'));
    domainInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await nextTick();
    await nextTick();

    expect(document.body.textContent).toContain('api.example.com');

    // Remove the '*' domain tag
    const removeButtons = Array.from(document.body.querySelectorAll('button[title="Remove domain"]')) as HTMLButtonElement[];
    expect(removeButtons.length).toBeGreaterThanOrEqual(1);
    removeButtons[0].click();
    await nextTick();
  });

  it('adds and removes listening ports with HTTP / HTTPS toggles', async () => {
    wrapper = mount(SiteDialog, {
      props: {
        open: true,
        site: null,
      },
      attachTo: document.body,
    });
    await nextTick();
    await nextTick();

    const addPortBtn = Array.from(document.body.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('ADD LISTENING PORT')
    );
    expect(addPortBtn).toBeTruthy();

    addPortBtn!.click();
    await nextTick();
    await nextTick();

    // Verify SSL Cert dropdown appears when HTTPS port is present
    expect(document.body.textContent).toContain('SSL Cert');
  });

  it('adds upstreams and reveals Load Balancing Algorithm selector when multiple upstreams exist', async () => {
    wrapper = mount(SiteDialog, {
      props: {
        open: true,
        site: null,
      },
      attachTo: document.body,
    });
    await nextTick();
    await nextTick();

    expect(document.body.textContent).not.toContain('Load Balancing Algorithm');

    const addUpstreamBtn = Array.from(document.body.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('ADD UPSTREAM')
    );
    expect(addUpstreamBtn).toBeTruthy();

    addUpstreamBtn!.click();
    await nextTick();
    await nextTick();

    // With 2 upstreams, Load Balancing Algorithm selector appears
    expect(document.body.textContent).toContain('Load Balancing Algorithm');
    expect(document.body.textContent).toContain('Weight');
  });

  it('emits sanitized site configuration on SUBMIT', async () => {
    wrapper = mount(SiteDialog, {
      props: {
        open: true,
        site: null,
      },
      attachTo: document.body,
    });
    await nextTick();
    await nextTick();

    // Enter app name
    const appNameInput = document.body.querySelector('input[placeholder="Application Name"]') as HTMLInputElement;
    expect(appNameInput).toBeTruthy();
    appNameInput.value = 'Payment Gateway';
    appNameInput.dispatchEvent(new Event('input'));
    await nextTick();

    // Submit form
    const submitBtn = Array.from(document.body.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('SUBMIT')
    );
    expect(submitBtn).toBeTruthy();
    submitBtn!.click();
    await nextTick();
    await nextTick();

    expect(wrapper.emitted('save')).toBeTruthy();
    const emittedData = wrapper.emitted('save')![0][0] as Partial<Site>;
    expect(emittedData.name).toBe('Payment Gateway');
    expect(emittedData.hostnames).toEqual(['*']);
    expect(emittedData.mode).toBe('defense');
    expect(emittedData.upstreams).toHaveLength(1);
    expect(emittedData.upstreams![0].dial).toBe('127.0.0.1:8080');
  });
});
