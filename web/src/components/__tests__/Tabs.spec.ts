import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, VueWrapper } from '@vue/test-utils'
import { nextTick, h } from 'vue'
import Tabs from '../ui/tabs/Tabs.vue'

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver
})

describe('Tabs.vue', () => {
  let wrapper: VueWrapper<any>

  afterEach(() => {
    if (wrapper) {
      wrapper.unmount()
    }
  })

  const sampleTabs = [
    { id: 'tab1', label: 'Overview' },
    { id: 'tab2', label: 'Security' },
    { id: 'tab3', label: 'Settings' },
  ]

  it('renders all tabs with correct labels and role attributes', () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElements.length).toBe(3)
    expect(tabElements[0].text()).toContain('Overview')
    expect(tabElements[1].text()).toContain('Security')
    expect(tabElements[2].text()).toContain('Settings')

    expect(tabElements[0].attributes('role')).toBe('tab')
    expect(tabElements[0].attributes('aria-selected')).toBe('true')
    expect(tabElements[1].attributes('aria-selected')).toBe('false')
  })

  it('sets initial active tab from activeTab prop', () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        activeTab: 'tab2',
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElements[0].attributes('aria-selected')).toBe('false')
    expect(tabElements[1].attributes('aria-selected')).toBe('true')
  })

  it('sets initial active tab from modelValue prop', () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        modelValue: 'tab3',
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElements[2].attributes('aria-selected')).toBe('true')
  })

  it('emits events and calls onTabChange callback on tab click', async () => {
    const onTabChange = vi.fn()
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        modelValue: 'tab1',
        onTabChange,
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    await tabElements[1].trigger('click')

    expect(wrapper.emitted('update:modelValue')).toBeTruthy()
    expect(wrapper.emitted('update:modelValue')![0]).toEqual(['tab2'])

    expect(wrapper.emitted('tabChange')).toBeTruthy()
    expect(wrapper.emitted('tabChange')![0]).toEqual(['tab2'])

    expect(onTabChange).toHaveBeenCalledWith('tab2')
  })

  it('responds to hover events on tab items', async () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
      },
    })

    const hoverHighlight = wrapper.find('[data-testid="tab-hover-highlight"]')
    expect(hoverHighlight.exists()).toBe(true)
    // Initially opacity is 0
    expect(hoverHighlight.attributes('style')).toContain('opacity: 0')

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    await tabElements[1].trigger('mouseenter')
    await nextTick()

    // Hovered index is now active, opacity should be 1
    expect(hoverHighlight.attributes('style')).toContain('opacity: 1')

    await tabElements[1].trigger('mouseleave')
    await nextTick()

    expect(hoverHighlight.attributes('style')).toContain('opacity: 0')
  })

  it('updates active tab when activeTab prop changes dynamically', async () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        activeTab: 'tab1',
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElements[0].attributes('aria-selected')).toBe('true')

    await wrapper.setProps({ activeTab: 'tab3' })
    await nextTick()

    expect(tabElements[0].attributes('aria-selected')).toBe('false')
    expect(tabElements[2].attributes('aria-selected')).toBe('true')
  })

  it('renders tab icons when provided', () => {
    const DummyIcon = () => h('svg', { 'data-testid': 'dummy-icon' })
    const tabsWithIcon = [
      { id: 'tab1', label: 'Overview', icon: DummyIcon },
    ]

    wrapper = mount(Tabs, {
      props: {
        tabs: tabsWithIcon,
      },
    })

    expect(wrapper.find('[data-testid="dummy-icon"]').exists()).toBe(true)
  })

  it('handles empty tabs array gracefully without throwing', () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: [],
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElements.length).toBe(0)
    const activeIndicator = wrapper.find('[data-testid="tab-active-indicator"]')
    expect(activeIndicator.exists()).toBe(true)
  })

  it('computes active indicator style from element offsetLeft and offsetWidth', async () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        activeTab: 'tab2',
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    // Mock dimensions on tab elements
    Object.defineProperty(tabElements[1].element, 'offsetLeft', { value: 120, configurable: true })
    Object.defineProperty(tabElements[1].element, 'offsetWidth', { value: 85, configurable: true })

    // Trigger tab switch to force active style recalculation
    await tabElements[1].trigger('click')
    await nextTick()

    const activeIndicator = wrapper.find('[data-testid="tab-active-indicator"]')
    expect(activeIndicator.attributes('style')).toContain('left: 120px')
    expect(activeIndicator.attributes('style')).toContain('width: 85px')
  })

  it('supports keyboard navigation via arrow keys, enter, and space', async () => {
    const onTabChange = vi.fn()
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        activeTab: 'tab1',
        onTabChange,
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElements[0].attributes('aria-selected')).toBe('true')

    // Navigate right via ArrowRight
    await tabElements[0].trigger('keydown', { key: 'ArrowRight' })
    await nextTick()

    expect(wrapper.emitted('tabChange')![0]).toEqual(['tab2'])
    expect(onTabChange).toHaveBeenCalledWith('tab2')
    expect(tabElements[1].attributes('aria-selected')).toBe('true')

    // Navigate left via ArrowLeft (cycles back to tab1)
    await tabElements[1].trigger('keydown', { key: 'ArrowLeft' })
    await nextTick()

    expect(wrapper.emitted('tabChange')![1]).toEqual(['tab1'])
    expect(tabElements[0].attributes('aria-selected')).toBe('true')

    // Press Space or Enter to select
    await tabElements[2].trigger('keydown', { key: 'Enter' })
    await nextTick()

    expect(wrapper.emitted('tabChange')![2]).toEqual(['tab3'])
    expect(tabElements[2].attributes('aria-selected')).toBe('true')
  })

  it('re-measures layout when web fonts finish loading via document.fonts.ready', async () => {
    let fontCallback: () => void = () => {}
    const fontPromise = new Promise<void>((resolve) => {
      fontCallback = resolve
    })

    Object.defineProperty(document, 'fonts', {
      value: { ready: fontPromise },
      configurable: true,
    })

    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        activeTab: 'tab1',
      },
    })

    const tabElements = wrapper.findAll('[data-testid="tab-item"]')
    Object.defineProperty(tabElements[0].element, 'offsetLeft', { value: 0, configurable: true })
    Object.defineProperty(tabElements[0].element, 'offsetWidth', { value: 110, configurable: true })

    fontCallback()
    await fontPromise
    await nextTick()

    const activeIndicator = wrapper.find('[data-testid="tab-active-indicator"]')
    expect(activeIndicator.attributes('style')).toContain('width: 110px')
  })

  it('handles dynamic tabs reduction without out-of-bounds error', async () => {
    wrapper = mount(Tabs, {
      props: {
        tabs: sampleTabs,
        activeTab: 'tab3',
      },
    })

    const tabElementsBefore = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElementsBefore[2].attributes('aria-selected')).toBe('true')

    // Dynamically shrink tabs list to only 1 tab
    await wrapper.setProps({
      tabs: [{ id: 'onlyOne', label: 'Only One' }],
      activeTab: 'onlyOne',
    })
    await nextTick()

    const tabElementsAfter = wrapper.findAll('[data-testid="tab-item"]')
    expect(tabElementsAfter.length).toBe(1)
    expect(tabElementsAfter[0].attributes('aria-selected')).toBe('true')
  })
})
