<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <tbody :class="cn('divide-y divide-[#2d3440]/60 [&_tr:last-child]:border-0', props.class)">
    <slot />
  </tbody>
</template>
