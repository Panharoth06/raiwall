<script setup lang="ts">
import { inject, computed, type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  value: string
  class?: HTMLAttributes['class']
}>()

const activeTab = inject<any>('tabsActiveTab', null)
const isVisible = computed(() => {
  if (!activeTab) return true
  return (activeTab.value ?? activeTab) === props.value
})
</script>

<template>
  <div
    v-if="isVisible"
    role="tabpanel"
    :class="
      cn(
        'mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        props.class
      )
    "
  >
    <slot />
  </div>
</template>
