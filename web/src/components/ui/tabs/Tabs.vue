<script setup lang="ts">
import {
  ref,
  computed,
  watch,
  onMounted,
  onBeforeUpdate,
  onBeforeUnmount,
  nextTick,
  provide,
  type HTMLAttributes,
} from 'vue'
import { cn } from '@/lib/utils'

defineOptions({
  name: 'Tabs',
})

export interface Tab {
  id: string
  label: string
  icon?: any
  description?: string
  [key: string]: any
}

export interface TabsProps {
  tabs: Tab[]
  activeTab?: string
  modelValue?: string
  class?: HTMLAttributes['class']
  onTabChange?: (tabId: string) => void
}

const props = withDefaults(defineProps<TabsProps>(), {
  tabs: () => [],
})

const emit = defineEmits<{
  (e: 'update:modelValue', tabId: string): void
  (e: 'tabChange', tabId: string): void
  (e: 'tab-change', tabId: string): void
}>()

const containerRef = ref<HTMLDivElement | null>(null)
const tabRefs = ref<(HTMLDivElement | null)[]>([])
const hoveredIndex = ref<number | null>(null)
const activeIndex = ref<number>(0)
const hoverStyle = ref<Record<string, string>>({})
const activeStyle = ref<{ left: string; width: string }>({ left: '0px', width: '0px' })

const selectedTabId = computed(() => props.modelValue ?? props.activeTab)

const setTabRef = (el: unknown, index: number) => {
  if (el) {
    tabRefs.value[index] = el as HTMLDivElement
  } else {
    delete tabRefs.value[index]
  }
}

onBeforeUpdate(() => {
  tabRefs.value = []
})

// Sync activeIndex with selectedTabId or tabs prop
const syncActiveIndex = () => {
  if (selectedTabId.value !== undefined) {
    const idx = props.tabs.findIndex((t) => t.id === selectedTabId.value)
    if (idx !== -1) {
      activeIndex.value = idx
      return
    }
  }
  if (activeIndex.value >= props.tabs.length) {
    activeIndex.value = 0
  }
}

const updateHoverStyle = () => {
  if (hoveredIndex.value !== null) {
    const hoveredElement = tabRefs.value[hoveredIndex.value]
    if (hoveredElement) {
      const offsetLeft = hoveredElement.offsetLeft ?? 0
      const offsetWidth = hoveredElement.offsetWidth ?? 0
      hoverStyle.value = {
        left: `${offsetLeft}px`,
        width: `${offsetWidth}px`,
      }
    }
  }
}

const updateActiveStyle = () => {
  if (!props.tabs.length) {
    activeStyle.value = { left: '0px', width: '0px' }
    return
  }
  const activeElement = tabRefs.value[activeIndex.value] || tabRefs.value[0]
  if (activeElement) {
    const offsetLeft = activeElement.offsetLeft ?? 0
    const offsetWidth = activeElement.offsetWidth ?? 0
    activeStyle.value = {
      left: `${offsetLeft}px`,
      width: `${offsetWidth}px`,
    }
  }
}

watch(
  () => [selectedTabId.value, props.tabs],
  () => {
    syncActiveIndex()
    nextTick(() => {
      updateActiveStyle()
    })
  },
  { immediate: true, deep: true }
)

watch(hoveredIndex, () => {
  updateHoverStyle()
})

watch(activeIndex, () => {
  nextTick(() => {
    updateActiveStyle()
  })
})

const selectTab = (tab: Tab, index: number) => {
  activeIndex.value = index
  updateActiveStyle()
  emit('update:modelValue', tab.id)
  emit('tabChange', tab.id)
  emit('tab-change', tab.id)
  props.onTabChange?.(tab.id)
}

const selectNextTab = (currentIndex: number) => {
  if (!props.tabs.length) return
  const nextIndex = (currentIndex + 1) % props.tabs.length
  const nextTab = props.tabs[nextIndex]
  if (nextTab) {
    selectTab(nextTab, nextIndex)
    tabRefs.value[nextIndex]?.focus()
  }
}

const selectPrevTab = (currentIndex: number) => {
  if (!props.tabs.length) return
  const prevIndex = (currentIndex - 1 + props.tabs.length) % props.tabs.length
  const prevTab = props.tabs[prevIndex]
  if (prevTab) {
    selectTab(prevTab, prevIndex)
    tabRefs.value[prevIndex]?.focus()
  }
}

let resizeObserver: ResizeObserver | null = null

const handleResize = () => {
  updateActiveStyle()
  if (hoveredIndex.value !== null) {
    updateHoverStyle()
  }
}

onMounted(() => {
  syncActiveIndex()
  nextTick(() => {
    requestAnimationFrame(() => {
      updateActiveStyle()
    })
  })

  // Recalculate layout when web fonts load to prevent layout shift misalignments
  if (typeof document !== 'undefined' && document.fonts?.ready) {
    document.fonts.ready.then(() => {
      updateActiveStyle()
    })
  }

  if (typeof ResizeObserver !== 'undefined' && containerRef.value) {
    resizeObserver = new ResizeObserver(() => {
      handleResize()
    })
    resizeObserver.observe(containerRef.value)
  }

  if (typeof window !== 'undefined') {
    window.addEventListener('resize', handleResize)
  }
})

onBeforeUnmount(() => {
  if (resizeObserver) {
    resizeObserver.disconnect()
  }
  if (typeof window !== 'undefined') {
    window.removeEventListener('resize', handleResize)
  }
})

// Provide active tab ID to children (e.g. TabsContent)
provide('tabsActiveTab', computed(() => props.tabs[activeIndex.value]?.id ?? selectedTabId.value))
</script>

<template>
  <div 
    ref="containerRef" 
    :class="cn('relative', props.class)"
  >
    <div class="relative">
      <!-- Hover Highlight -->
      <div
        data-testid="tab-hover-highlight"
        class="absolute h-[30px] transition-all duration-300 ease-out bg-[#0e0f1114] dark:bg-[#ffffff1a] rounded-[6px] flex items-center pointer-events-none"
        :style="{
          ...hoverStyle,
          opacity: hoveredIndex !== null ? 1 : 0,
        }"
      />

      <!-- Active Indicator -->
      <div
        data-testid="tab-active-indicator"
        class="absolute bottom-[-6px] h-[2px] bg-[#0e0f11] dark:bg-white transition-all duration-300 ease-out pointer-events-none"
        :style="activeStyle"
      />

      <!-- Tabs -->
      <div class="relative flex space-x-[6px] items-center" role="tablist">
        <div
          v-for="(tab, index) in tabs"
          :key="tab.id"
          :ref="(el) => setTabRef(el, index)"
          data-testid="tab-item"
          role="tab"
          tabindex="0"
          :aria-selected="index === activeIndex"
          :class="cn(
            'px-3 py-2 cursor-pointer transition-colors duration-300 h-[30px] select-none rounded-[6px] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#2574F5]',
            index === activeIndex 
              ? 'text-[#0e0e10] dark:text-white font-medium' 
              : 'text-[#0e0f1199] dark:text-[#ffffff99]'
          )"
          @mouseenter="hoveredIndex = index"
          @mouseleave="hoveredIndex = null"
          @click="selectTab(tab, index)"
          @keydown.arrow-right.prevent="selectNextTab(index)"
          @keydown.arrow-left.prevent="selectPrevTab(index)"
          @keydown.enter.prevent="selectTab(tab, index)"
          @keydown.space.prevent="selectTab(tab, index)"
        >
          <div class="text-sm font-medium leading-5 whitespace-nowrap flex items-center justify-center h-full gap-2">
            <component :is="tab.icon" v-if="tab.icon" class="w-3.5 h-3.5 transition-colors shrink-0" />
            <slot name="tab" :tab="tab" :index="index" :is-active="index === activeIndex">
              <span>{{ tab.label }}</span>
            </slot>
          </div>
        </div>
      </div>
    </div>
    <slot />
  </div>
</template>
