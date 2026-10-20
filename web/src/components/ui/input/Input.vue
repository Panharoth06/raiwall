<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
  type?: string
  placeholder?: string
  disabled?: boolean
  required?: boolean
}>()

const modelValue = defineModel<string | number>()
</script>

<template>
  <input
    v-model="modelValue"
    :type="type || 'text'"
    :disabled="disabled"
    :required="required"
    :placeholder="placeholder"
    :class="
      cn(
        'flex h-9 w-full rounded-md border border-[#2d3440] bg-[#1e222a] px-3 py-1 text-xs text-white placeholder:text-slate-500 shadow-none focus-visible:outline-none focus-visible:border-[#2574F5] focus-visible:ring-1 focus-visible:ring-[#2574F5] disabled:cursor-not-allowed disabled:opacity-50 transition-colors font-sans',
        props.class
      )
    "
  />
</template>
