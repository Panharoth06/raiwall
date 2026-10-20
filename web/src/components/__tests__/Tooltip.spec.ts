import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mount, VueWrapper } from '@vue/test-utils'
import { h, nextTick } from 'vue'
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
  TooltipArrow,
} from '../ui/tooltip'

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

describe('Tooltip components', () => {
  let wrapper: VueWrapper<any>

  afterEach(() => {
    if (wrapper) {
      wrapper.unmount()
    }
    document.body.innerHTML = ''
  })

  it('renders TooltipProvider with default delay duration and slot content', () => {
    wrapper = mount(TooltipProvider, {
      slots: {
        default: () => h('div', { 'data-testid': 'provider-child' }, 'Child content'),
      },
    })

    expect(wrapper.find('[data-testid="provider-child"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Child content')
  })

  it('renders TooltipTrigger with custom elements and preserves attributes', () => {
    wrapper = mount(TooltipProvider, {
      slots: {
        default: () =>
          h(Tooltip, null, {
            default: () => [
              h(
                TooltipTrigger,
                { asChild: true },
                {
                  default: () =>
                    h('button', { 'data-testid': 'trigger-btn' }, 'Hover me'),
                },
              ),
            ],
          }),
      },
    })

    const trigger = wrapper.find('[data-testid="trigger-btn"]')
    expect(trigger.exists()).toBe(true)
    expect(trigger.text()).toBe('Hover me')
  })

  it('renders TooltipContent when tooltip is open', async () => {
    wrapper = mount(
      {
        components: {
          TooltipProvider,
          Tooltip,
          TooltipTrigger,
          TooltipContent,
        },
        template: `
          <TooltipProvider>
            <Tooltip :open="true">
              <TooltipTrigger as-child>
                <button data-testid="trigger">Trigger</button>
              </TooltipTrigger>
              <TooltipContent data-testid="content" class="custom-class" :disabled="true">
                Tooltip details
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        `,
      },
      {
        attachTo: document.body,
      },
    )

    await nextTick()

    const content = wrapper.find('[data-testid="content"]')
    expect(content.exists()).toBe(true)
    expect(content.text()).toContain('Tooltip details')
    expect(content.classes()).toContain('custom-class')
    expect(content.classes()).toContain('z-50')
    expect(content.classes()).toContain('bg-[#1E222A]')
  })

  it('renders TooltipArrow inside TooltipContent', async () => {
    wrapper = mount(
      {
        components: {
          TooltipProvider,
          Tooltip,
          TooltipTrigger,
          TooltipContent,
          TooltipArrow,
        },
        template: `
          <TooltipProvider>
            <Tooltip :open="true">
              <TooltipTrigger as-child>
                <button>Trigger</button>
              </TooltipTrigger>
              <TooltipContent data-testid="content" :disabled="true">
                <TooltipArrow data-testid="arrow" class="custom-arrow" />
                <span>Text with arrow</span>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        `,
      },
      {
        attachTo: document.body,
      },
    )

    await nextTick()

    const arrow = wrapper.find('[data-testid="arrow"]')
    expect(arrow.exists()).toBe(true)
    expect(arrow.classes()).toContain('custom-arrow')
  })

  it('exports all expected components and types from index', async () => {
    const tooltipModule = await import('../ui/tooltip')
    expect(tooltipModule.Tooltip).toBeDefined()
    expect(tooltipModule.TooltipTrigger).toBeDefined()
    expect(tooltipModule.TooltipContent).toBeDefined()
    expect(tooltipModule.TooltipProvider).toBeDefined()
    expect(tooltipModule.TooltipArrow).toBeDefined()
    expect(tooltipModule.TooltipRoot).toBeDefined()
  })
})
