import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import Progress from '../progress/Progress.vue'

describe('Progress.vue', () => {
  it('renders indicator with 50% translation for modelValue=50 and max=100', () => {
    const wrapper = mount(Progress, {
      props: {
        modelValue: 50,
        max: 100,
        variant: 'primary',
      },
    })
    const indicator = wrapper.find('.bg-primary')
    expect(indicator.exists()).toBe(true)
    expect(indicator.attributes('style')).toContain('translateX(-50%)')
  })

  it('renders 100% translation for full modelValue', () => {
    const wrapper = mount(Progress, {
      props: {
        modelValue: 20,
        max: 20,
        variant: 'threat',
      },
    })
    const indicator = wrapper.find('.bg-threat')
    expect(indicator.exists()).toBe(true)
    expect(indicator.attributes('style')).toContain('translateX(-0%)')
  })
})
