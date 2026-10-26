<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
  placeholder?: string
  disabled?: boolean
  rows?: number
  readonly?: boolean
}>()

const modelValue = defineModel<string>()
</script>

<template>
  <textarea
    v-model="modelValue"
    :disabled="disabled"
    :readonly="readonly"
    :rows="rows || 6"
    :placeholder="placeholder"
    :class="
      cn(
        'flex w-full rounded-md border border-input bg-card px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground shadow-none focus-visible:outline-none focus-visible:border-primary focus-visible:ring-0 disabled:cursor-not-allowed disabled:opacity-50 transition-colors font-mono resize-y',
        props.class
      )
    "
  />
</template>
