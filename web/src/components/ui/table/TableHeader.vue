<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <thead :class="cn('sticky top-0 z-10 bg-muted text-muted-foreground [&>tr]:border-0 [&>tr:hover]:bg-transparent', props.class)">
    <slot />
  </thead>
</template>
