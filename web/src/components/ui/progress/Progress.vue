<script setup lang="ts">
import { computed, type HTMLAttributes } from 'vue'
import {
  ProgressIndicator,
  ProgressRoot,
} from 'radix-vue'
import { cn } from '@/lib/utils'

interface Props {
  modelValue?: number | null
  max?: number
  getValueLabel?: (value: number, max: number) => string
  class?: HTMLAttributes['class']
  indicatorClass?: HTMLAttributes['class']
  variant?: 'default' | 'primary' | 'threat' | 'success' | 'warning' | 'muted'
}

const props = withDefaults(defineProps<Props>(), {
  modelValue: 0,
  max: 100,
  variant: 'default',
})

const percentage = computed(() => {
  const current = props.modelValue ?? 0
  const max = props.max || 100
  if (max <= 0) return 0
  const pct = (current / max) * 100
  return Math.min(100, Math.max(0, pct))
})

const variantClass = computed(() => {
  switch (props.variant) {
    case 'threat':
      return 'bg-threat'
    case 'success':
      return 'bg-success'
    case 'warning':
      return 'bg-warning'
    case 'muted':
      return 'bg-muted-foreground'
    case 'primary':
    case 'default':
    default:
      return 'bg-primary'
  }
})
</script>

<template>
  <ProgressRoot
    :class="
      cn(
        'relative h-2 w-full overflow-hidden rounded-full bg-muted',
        props.class,
      )
    "
    :model-value="props.modelValue ?? 0"
    :max="props.max"
    :get-value-label="props.getValueLabel"
  >
    <ProgressIndicator
      :class="
        cn(
          'h-full w-full flex-1 transition-all duration-300 ease-out',
          variantClass,
          props.indicatorClass,
        )
      "
      :style="`transform: translateX(-${100 - percentage}%);`"
    />
  </ProgressRoot>
</template>
