<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <thead :class="cn('bg-muted text-muted-foreground uppercase tracking-wider font-semibold border-b border-border', props.class)">
    <slot />
  </thead>
</template>
