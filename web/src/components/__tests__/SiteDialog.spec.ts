import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { nextTick } from 'vue';
import SiteDialog from '../SiteDialog.vue';
import type { ManagedCertificate, Site } from '@/api/client';

const baseSite = (overrides: Partial<Site> = {}): Site => ({
  id: 'site-1',
  name: 'Internal Portal',
  hostnames: ['portal.example.com'],
  mode: 'defense',
  ports: [
    { port: 80, scheme: 'http' },
    { port: 443, scheme: 'https' },
  ],
  ssl_mode: 'auto',
  routing_type: 'proxy',
  load_balancing: 'round_robin',
  upstreams: [{ dial: '10.0.0.5:8080', weight: 2 }],
  block_status_code: 403,
  offline_status_code: 503,
  ...overrides,
});

const certificate = (overrides: Partial<ManagedCertificate> = {}): ManagedCertificate => ({
  id: 'cert-1',
  name: 'portal cert',
  domains: ['portal.example.com'],
  source: 'self_signed',
  auto_renew: true,
  status: 'valid',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  ...overrides,
});

const findButton = (label: string): HTMLButtonElement | undefined =>
  Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.includes(label));

const mountDialog = (props: Record<string, unknown> = {}) =>
  mount(SiteDialog, {
    props: { open: true, site: null, ...props },
    attachTo: document.body,
  });

describe('SiteDialog.vue (application registration)', () => {
  let wrapper: ReturnType<typeof mount> | undefined;

  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = undefined;
    document.body.innerHTML = '';
  });

  it('renders defaults: wildcard domain, listeners, TLS mode, and routing', async () => {
    wrapper = mountDialog();
    await nextTick();
    await nextTick();

    const bodyText = document.body.textContent || '';
    expect(bodyText).toContain('Add Application');
    expect(bodyText).toContain('Domain');
    expect(bodyText).toContain('*');
    expect(bodyText).toContain('Listening port');
    expect(bodyText).toContain(':8080');
    expect(bodyText).toContain('HTTP');
    expect(bodyText).toContain('HTTPS');
    expect(bodyText).toContain('TLS certificate');
    expect(bodyText).toContain('Reverse Proxy');
    expect(bodyText).toContain('Static Files');
    expect(bodyText).toContain('Redirect');
    expect(bodyText).toContain('Upstream');
    expect(bodyText).toContain('SUBMIT');
    expect(bodyText).toContain('CANCEL');
  });

  it('adds and removes domain tags', async () => {
    wrapper = mountDialog();
    await nextTick();

    const domainInput = document.body.querySelector('input[placeholder*="www.example.com"]') as HTMLInputElement;
    expect(domainInput).toBeTruthy();

    domainInput.value = 'api.example.com';
    domainInput.dispatchEvent(new Event('input'));
    domainInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await nextTick();

    expect(document.body.textContent).toContain('api.example.com');

    const removeButtons = Array.from(
      document.body.querySelectorAll('button[title="Remove domain"]')
    ) as HTMLButtonElement[];
    expect(removeButtons.length).toBeGreaterThanOrEqual(1);
    removeButtons[0].click();
    await nextTick();
  });

  it('adds listening ports and keeps the TLS picker available', async () => {
    wrapper = mountDialog();
    await nextTick();

    findButton('ADD LISTENING PORT')!.click();
    await nextTick();

    expect(document.body.textContent).toContain('TLS certificate');
  });

  it('reveals the load-balancing selector when a second upstream is added', async () => {
    wrapper = mountDialog();
    await nextTick();

    expect(document.body.textContent).not.toContain('Load Balancing Algorithm');

    findButton('ADD UPSTREAM')!.click();
    await nextTick();
    await nextTick();

    expect(document.body.textContent).toContain('Load Balancing Algorithm');
    expect(document.body.textContent).toContain('Weight');
  });

  it('reveals static and redirect fields only for their routing mode', async () => {
    wrapper = mountDialog();
    await nextTick();

    findButton('Static Files')!.click();
    await nextTick();
    expect(document.body.textContent).toContain('Document root');
    expect(document.body.textContent).not.toContain('Redirect target');

    findButton('Redirect')!.click();
    await nextTick();
    expect(document.body.textContent).toContain('Redirect target');
    expect(document.body.textContent).not.toContain('Document root');
  });

  it('emits a full payload with routing, TLS, and ports on SUBMIT', async () => {
    wrapper = mountDialog();
    await nextTick();

    const appNameInput = document.body.querySelector('input[placeholder="Application Name"]') as HTMLInputElement;
    appNameInput.value = 'Payment Gateway';
    appNameInput.dispatchEvent(new Event('input'));
    await nextTick();

    findButton('SUBMIT')!.click();
    await nextTick();
    await nextTick();

    expect(wrapper.emitted('save')).toBeTruthy();
    const payload = wrapper.emitted('save')![0][0] as Partial<Site>;
    expect(payload.name).toBe('Payment Gateway');
    expect(payload.hostnames).toEqual(['*']);
    expect(payload.mode).toBe('defense');
    expect(payload.routing_type).toBe('proxy');
    expect(payload.ssl_mode).toBe('auto');
    expect(payload.load_balancing).toBe('round_robin');
    expect(payload.ports).toEqual([
      { port: 80, scheme: 'http' },
      { port: 443, scheme: 'https' },
    ]);
    expect(payload.upstreams).toHaveLength(1);
    expect(payload.upstreams![0].dial).toBe('127.0.0.1:8080');
  });

  it('hydrates an existing static site with a manual certificate', async () => {
    wrapper = mountDialog({
      site: baseSite({
        ssl_mode: 'manual',
        certificate_id: 'cert-1',
        routing_type: 'static',
        document_root: '/srv/www/portal',
        load_balancing: 'least_conn',
        description: 'Serves the intranet bundle',
      }),
      certificates: [certificate()],
    });
    await nextTick();
    await nextTick();

    expect(document.body.textContent).toContain('Edit Application');
    const rootInput = document.body.querySelector('input[placeholder="/srv/www/site"]') as HTMLInputElement;
    expect(rootInput?.value).toBe('/srv/www/portal');

    findButton('SUBMIT')!.click();
    await nextTick();

    const payload = wrapper.emitted('save')![0][0] as Partial<Site>;
    expect(payload.id).toBe('site-1');
    expect(payload.description).toBe('Serves the intranet bundle');
    expect(payload.routing_type).toBe('static');
    expect(payload.document_root).toBe('/srv/www/portal');
    expect(payload.ssl_mode).toBe('manual');
    expect(payload.certificate_id).toBe('cert-1');
    expect(payload.load_balancing).toBe('least_conn');
  });

  it('blocks submission when manual TLS has no certificate', async () => {
    wrapper = mountDialog({
      site: baseSite({ ssl_mode: 'manual', certificate_id: '' }),
    });
    await nextTick();
    await nextTick();

    findButton('SUBMIT')!.click();
    await nextTick();

    expect(wrapper.emitted('save')).toBeFalsy();
    expect(document.body.textContent).toContain('Select a managed certificate');
  });

  it('blocks submission for invalid upstream and redirect values', async () => {
    wrapper = mountDialog();
    await nextTick();

    const upstreamInput = document.body.querySelector(
      'input[placeholder^="http://192.168.1.10:8080"]'
    ) as HTMLInputElement;
    upstreamInput.value = 'not a host';
    upstreamInput.dispatchEvent(new Event('input'));
    await nextTick();

    findButton('SUBMIT')!.click();
    await nextTick();
    expect(wrapper.emitted('save')).toBeFalsy();
    expect(document.body.textContent).toContain('Invalid upstream address');
  });

  it('flags a redirect target without scheme', async () => {
    wrapper = mountDialog();
    await nextTick();

    findButton('Redirect')!.click();
    await nextTick();

    const redirectInput = document.body.querySelector(
      'input[placeholder="https://example.com/landing"]'
    ) as HTMLInputElement;
    redirectInput.value = 'example.com/landing';
    redirectInput.dispatchEvent(new Event('input'));
    await nextTick();

    findButton('SUBMIT')!.click();
    await nextTick();

    expect(wrapper.emitted('save')).toBeFalsy();
    expect(document.body.textContent).toContain('Redirect target must be an absolute URL');
  });
});
