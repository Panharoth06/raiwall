import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import { nextTick } from 'vue'
import CertificatesPanel from '../CertificatesPanel.vue'
import { api, type ManagedCertificate } from '@/api/client'

const certificate = (overrides: Partial<ManagedCertificate> = {}): ManagedCertificate => ({
  id: 'cert-1',
  name: 'primary',
  domains: ['app.example.com'],
  source: 'self_signed',
  cert_pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
  fingerprint_sha256: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-01-01T00:00:00Z',
  auto_renew: true,
  status: 'valid',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  ...overrides,
})

const findButton = (label: string): HTMLButtonElement | undefined =>
  Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.includes(label))

describe('CertificatesPanel.vue', () => {
  let wrapper: ReturnType<typeof mount> | undefined

  beforeEach(() => {
    setActivePinia(createPinia())
    vi.restoreAllMocks()
    document.body.innerHTML = ''
    vi.spyOn(api, 'getDraftDiff').mockResolvedValue({ has_changes: false, diffs: [] })
  })

  afterEach(() => {
    wrapper?.unmount()
    wrapper = undefined
    document.body.innerHTML = ''
  })

  it('renders the empty state and creates a self-signed certificate', async () => {
    vi.spyOn(api, 'listCertificates').mockResolvedValue([])
    const created = certificate()
    const create = vi.spyOn(api, 'createCertificate').mockResolvedValue(created)

    wrapper = mount(CertificatesPanel, { attachTo: document.body })
    await flushPromises()
    await nextTick()

    expect(document.body.textContent).toContain('No certificates managed yet')

    findButton('Add Certificate')!.click()
    await flushPromises()
    await nextTick()

    const domainInput = document.body.querySelector(
      'input[placeholder*="app.example.com"]'
    ) as HTMLInputElement
    domainInput.value = 'portal.example.com'
    domainInput.dispatchEvent(new Event('input'))
    domainInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    await nextTick()

    findButton('SUBMIT')!.click()
    await flushPromises()
    await nextTick()

    expect(create).toHaveBeenCalledTimes(1)
    const payload = create.mock.calls[0][0]
    expect(payload.source).toBe('self_signed')
    expect(payload.domains).toEqual(['portal.example.com'])
    expect(payload.auto_renew).toBe(true)
  })

  it('renders certificate status and renews a self-signed certificate', async () => {
    vi.spyOn(api, 'listCertificates').mockResolvedValue([
      certificate(),
      certificate({
        id: 'cert-2',
        name: 'expiring',
        domains: ['*.example.com'],
        status: 'expiring',
        not_after: '2026-11-01T00:00:00Z',
      }),
    ])
    const renew = vi.spyOn(api, 'renewCertificate').mockResolvedValue(certificate({ name: 'primary' }))

    wrapper = mount(CertificatesPanel, { attachTo: document.body })
    await flushPromises()
    await nextTick()

    expect(document.body.textContent).toContain('primary')
    expect(document.body.textContent).toContain('expiring')
    expect(document.body.textContent).toContain('need attention')

    const renewButton = document.body.querySelector(
      'button[aria-label="Renew primary"]'
    ) as HTMLButtonElement
    expect(renewButton).toBeTruthy()
    renewButton.click()
    await flushPromises()
    await nextTick()

    expect(renew).toHaveBeenCalledWith('cert-1')
    expect(document.body.textContent).toContain('Renewed primary')
  })

  it('downloads PEM material through a blob URL', async () => {
    vi.spyOn(api, 'listCertificates').mockResolvedValue([certificate()])
    const blob = new Blob(['-----BEGIN CERTIFICATE-----'], { type: 'application/x-pem-file' })
    vi.spyOn(api, 'downloadCertificate').mockResolvedValue(blob)
    const createObjectURL = vi.fn(() => 'blob:mock')
    const revokeObjectURL = vi.fn()
    Object.assign(URL, { createObjectURL, revokeObjectURL })

    wrapper = mount(CertificatesPanel, { attachTo: document.body })
    await flushPromises()
    await nextTick()

    const downloadButton = document.body.querySelector(
      'button[aria-label="Download primary"]'
    ) as HTMLButtonElement
    downloadButton.click()
    await flushPromises()
    await nextTick()

    expect(api.downloadCertificate).toHaveBeenCalledWith('cert-1')
    expect(createObjectURL).toHaveBeenCalled()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock')
  })

  it('surfaces the delete conflict when a site still uses the certificate', async () => {
    vi.spyOn(api, 'listCertificates').mockResolvedValue([certificate()])
    vi.spyOn(api, 'deleteCertificate').mockRejectedValue(
      new Error('API error (409): certificate is in use by site "portal"')
    )

    wrapper = mount(CertificatesPanel, { attachTo: document.body })
    await flushPromises()
    await nextTick()

    const deleteButton = document.body.querySelector(
      'button[aria-label="Delete primary"]'
    ) as HTMLButtonElement
    deleteButton.click()
    await flushPromises()
    await nextTick()

    findButton('Delete Certificate')!.click()
    await flushPromises()
    await nextTick()

    expect(document.body.textContent).toContain('in use by site')
  })
})
