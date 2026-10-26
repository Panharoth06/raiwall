import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import AttackMap2D from '../AttackMap2D.vue'

describe('AttackMap2D.vue (Apache ECharts Attack Flow)', () => {
  it('renders ECharts map container with correct testid', () => {
    const wrapper = mount(AttackMap2D, {
      props: {
        countries: [
          { key: 'China', count: 1200 },
          { key: 'Russia', count: 850 },
          { key: 'United States', count: 420 },
        ],
        dataMode: 'blocked',
      },
    })

    expect(wrapper.find('[data-testid="echarts-attack-map"]').exists()).toBe(true)
  })

  it('updates when dataMode switches between requests and blocked', async () => {
    const wrapper = mount(AttackMap2D, {
      props: {
        countries: [{ key: 'China', count: 100 }],
        dataMode: 'requests',
      },
    })

    expect(wrapper.find('[data-testid="echarts-attack-map"]').exists()).toBe(true)
    await wrapper.setProps({ dataMode: 'blocked' })
    expect(wrapper.find('[data-testid="echarts-attack-map"]').exists()).toBe(true)
  })

  it('renders interactive zoom and pan controls', async () => {
    const wrapper = mount(AttackMap2D, {
      props: {
        countries: [{ key: 'China', count: 100 }],
      },
    })

    const zoomInBtn = wrapper.find('[data-testid="map-zoom-in"]')
    const zoomOutBtn = wrapper.find('[data-testid="map-zoom-out"]')
    const resetBtn = wrapper.find('[data-testid="map-zoom-reset"]')

    expect(zoomInBtn.exists()).toBe(true)
    expect(zoomOutBtn.exists()).toBe(true)
    expect(resetBtn.exists()).toBe(true)

    // Trigger clicks without errors
    await zoomInBtn.trigger('click')
    await zoomOutBtn.trigger('click')
    await resetBtn.trigger('click')
  })

  it('renders zero mock data overlay when countries list is empty', () => {
    const wrapper = mount(AttackMap2D, {
      props: {
        countries: [],
      },
    })

    expect(wrapper.find('[data-testid="echarts-attack-map"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('No Geo Events Recorded')
  })
})
