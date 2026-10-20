<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <thead :class="cn('bg-[#14171d] text-slate-400 uppercase tracking-wider font-semibold border-b border-[#2d3440]', props.class)">
    <slot />
  </thead>
</template>
