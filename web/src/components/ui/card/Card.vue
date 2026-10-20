<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <div :class="cn('rounded-lg border border-[#2d3440] bg-[#1e222a] text-white shadow-none font-sans', props.class)">
    <slot />
  </div>
</template>
