import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mount, VueWrapper } from '@vue/test-utils'
import WafCommandCenter from '../WafCommandCenter.vue'

// Polyfill ResizeObserver and Pointer Capture for JSDOM
class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver
  window.HTMLElement.prototype.hasPointerCapture = () => false
  window.HTMLElement.prototype.setPointerCapture = () => {}
  window.HTMLElement.prototype.releasePointerCapture = () => {}
  window.HTMLElement.prototype.scrollIntoView = () => {}
})

describe('WafCommandCenter.vue', () => {
  let wrapper: VueWrapper<InstanceType<typeof WafCommandCenter>>

  afterEach(() => {
    if (wrapper) {
      wrapper.unmount()
    }
    document.body.innerHTML = ''
  })

  // Contract 1: Default Topology Render
  it('renders default topology with correct initial filters, destination upper summary, and 48 hub spikes', () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    // Filter button text is "Filters"
    const filterBtn = wrapper.find('[data-testid="filter-trigger-btn"]')
    expect(filterBtn.exists()).toBe(true)
    expect(filterBtn.text()).toBe('Filters')

    // dest-summary-upper contains "24" and "48.2M Reqs Inspected"
    const destUpper = wrapper.find('[data-testid="dest-summary-upper"]')
    expect(destUpper.exists()).toBe(true)
    expect(destUpper.text()).toContain('24')
    expect(destUpper.text()).toContain('48.2M Reqs Inspected')

    // Exactly 48 radial <line> ticks exist inside hub-waf-core
    const hubWafCore = wrapper.find('[data-testid="hub-waf-core"]')
    expect(hubWafCore.exists()).toBe(true)
    const radialTicks = hubWafCore.findAll('line')
    expect(radialTicks.length).toBe(48)
  })

  // Contract 2: Human Clients Orbital Expansion
  it('expands human clients sub-nodes upon clicking source-node-humans', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    // Initially sub-nodes should not exist
    expect(wrapper.find('[data-testid="subnode-verified"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="subnode-anonymous"]').exists()).toBe(false)

    // Trigger click on human clients node
    const humansNode = wrapper.find('[data-testid="source-node-humans"]')
    expect(humansNode.exists()).toBe(true)
    await humansNode.trigger('click')

    // Verified and Anonymous sub-nodes should be rendered in the DOM
    const subnodeVerified = wrapper.find('[data-testid="subnode-verified"]')
    expect(subnodeVerified.exists()).toBe(true)
    expect(subnodeVerified.text()).toContain('128.4k')
    expect(subnodeVerified.text()).toContain('VERIFIED SESSIONS')

    const subnodeAnonymous = wrapper.find('[data-testid="subnode-anonymous"]')
    expect(subnodeAnonymous.exists()).toBe(true)
    expect(subnodeAnonymous.text()).toContain('14.4k')
    expect(subnodeAnonymous.text()).toContain('ANONYMOUS / PROXY')

    // Clicking again collapses
    await humansNode.trigger('click')
    expect(wrapper.find('[data-testid="subnode-verified"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="subnode-anonymous"]').exists()).toBe(false)
  })

  // Contract 3: OWASP Top 10 Filter Mutation & Reset
  it('mutates topology when OWASP filter is toggled and resets properly', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    // Open filter popover
    const filterBtn = wrapper.find('[data-testid="filter-trigger-btn"]')
    await filterBtn.trigger('click')

    // Find and toggle switch
    const owaspSwitch = wrapper.find('[data-testid="owasp-filter-switch"]')
    expect(owaspSwitch.exists()).toBe(true)
    await owaspSwitch.trigger('click')

    // Filter button updates to "Filters: 1"
    expect(wrapper.find('[data-testid="filter-trigger-btn"]').text()).toBe('Filters: 1')

    // dest-summary-upper updates from "24" to "6" and "90.4k Attack Reqs"
    const destUpper = wrapper.find('[data-testid="dest-summary-upper"]')
    expect(destUpper.text()).toContain('6')
    expect(destUpper.text()).toContain('90.4k Attack Reqs')

    // Click Reset button
    const resetBtn = wrapper.find('[data-testid="filter-reset-btn"]')
    expect(resetBtn.exists()).toBe(true)
    await resetBtn.trigger('click')

    // Restores counter back to "24" and button text back to "Filters"
    expect(wrapper.find('[data-testid="dest-summary-upper"]').text()).toContain('24')
    expect(wrapper.find('[data-testid="filter-trigger-btn"]').text()).toBe('Filters')
  })

  // Contract 4: Traffic vs. Threats Mode Switch
  it('switches to Threats mode and updates upper summary metrics accordingly', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    // Click Threats mode button
    const threatsBtn = wrapper.find('[data-testid="mode-btn-threats"]')
    expect(threatsBtn.exists()).toBe(true)
    await threatsBtn.trigger('click')

    // dest-summary-upper displays "INJECTION VECTORS" and "2.14M Payloads Blocked"
    const destUpper = wrapper.find('[data-testid="dest-summary-upper"]')
    expect(destUpper.text()).toContain('INJECTION VECTORS')
    expect(destUpper.text()).toContain('2.14M Payloads Blocked')

    // Switch back to Traffic
    const trafficBtn = wrapper.find('[data-testid="mode-btn-traffic"]')
    await trafficBtn.trigger('click')
    expect(wrapper.find('[data-testid="dest-summary-upper"]').text()).toContain('API GATEWAY ROUTES')
  })

  // Contract 5: Tooltip Hover Lifecycle
  it('shows and hides topology tooltip on mouseenter and mouseleave', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    // Initially tooltip is not in DOM
    expect(wrapper.find('[data-testid="topology-tooltip"]').exists()).toBe(false)

    // Trigger mouseenter on an arc node item
    const arcNode = wrapper.find('[data-testid="arc-node-item"]')
    expect(arcNode.exists()).toBe(true)
    await arcNode.trigger('mouseenter', { clientX: 500, clientY: 200 })

    // Tooltip should be visible with non-empty content
    const tooltip = wrapper.find('[data-testid="topology-tooltip"]')
    expect(tooltip.exists()).toBe(true)
    expect(tooltip.text().trim().length).toBeGreaterThan(0)

    // Trigger mouseleave
    await arcNode.trigger('mouseleave')
    expect(wrapper.find('[data-testid="topology-tooltip"]').exists()).toBe(false)

    // Also test mouseenter on a Sankey ribbon
    const ribbon = wrapper.find('[data-testid="sankey-ribbon"]')
    expect(ribbon.exists()).toBe(true)
    await ribbon.trigger('mouseenter', { clientX: 600, clientY: 300 })

    const ribbonTooltip = wrapper.find('[data-testid="topology-tooltip"]')
    expect(ribbonTooltip.exists()).toBe(true)
    expect(ribbonTooltip.text().trim().length).toBeGreaterThan(0)

    await ribbon.trigger('mouseleave')
    expect(wrapper.find('[data-testid="topology-tooltip"]').exists()).toBe(false)
  })

  // Contract 6: Ingress Orbiting Perimeter Badges Micro-Telemetry
  it('updates cluster subtext with micro-telemetry when hovering perimeter badges', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    const botsCluster = wrapper.find('[data-testid="source-node-bots"]')
    expect(botsCluster.text()).toContain('3.4M Requests (68% Blocked)')

    // Find orbit badge group and trigger mouseenter
    const orbitBadge = botsCluster.find('.orbit-badge')
    expect(orbitBadge.exists()).toBe(true)
    await orbitBadge.trigger('mouseenter')

    // Subtext should update to micro-telemetry
    expect(botsCluster.text()).toContain('0.1 kB/s • TLS 1.3 Fingerprint')

    // Trigger mouseleave
    await orbitBadge.trigger('mouseleave')
    expect(botsCluster.text()).toContain('3.4M Requests (68% Blocked)')
  })

  // Contract 7: Dual Hubs and Lower Arc Summaries Verification
  it('verifies Edge & Bot Defense hub and lower summary in Traffic and Threats modes', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    // Edge & Bot Defense hub has 48 spikes
    const edgeHub = wrapper.find('[data-testid="hub-edge-defense"]')
    expect(edgeHub.exists()).toBe(true)
    expect(edgeHub.findAll('line').length).toBe(48)
    expect(edgeHub.text()).toContain('EDGE & BOT DEFENSE')
    expect(edgeHub.text()).toContain('18 Rate Policies, Geo-IP & JA4 Fingerprinting')

    // Lower summary in traffic mode
    const lowerSummary = wrapper.find('[data-testid="dest-summary-lower"]')
    expect(lowerSummary.exists()).toBe(true)
    expect(lowerSummary.text()).toContain('14')
    expect(lowerSummary.text()).toContain('WEB & MICROSERVICES')
    expect(lowerSummary.text()).toContain('11.9M Reqs Inspected')

    // Switch to threats mode
    await wrapper.find('[data-testid="mode-btn-threats"]').trigger('click')
    expect(lowerSummary.text()).toContain('4')
    expect(lowerSummary.text()).toContain('ABUSE & BOT VECTORS')
    expect(lowerSummary.text()).toContain('1.68M Requests Dropped')
  })

  // Contract 8: Tooltip Viewport Boundary Clamping
  it('clamps tooltip position so it never overflows screen edge', async () => {
    wrapper = mount(WafCommandCenter, {
      attachTo: document.body,
    })

    const arcNode = wrapper.find('[data-testid="arc-node-item"]')
    // Trigger near right edge (e.g. clientX: 1550 on a 1600 viewport)
    await arcNode.trigger('mouseenter', { clientX: 1550, clientY: 850 })

    const tooltip = wrapper.find('[data-testid="topology-tooltip"]')
    expect(tooltip.exists()).toBe(true)
    const style = tooltip.attributes('style')
    expect(style).toBeDefined()
    // left should be flipped to the left of the cursor (1550 - 275 - 16 = 1259)
    expect(style).toContain('left: 1259px')
  })
})
