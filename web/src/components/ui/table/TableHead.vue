<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <th :class="cn('h-9 whitespace-nowrap border-b border-border px-3 text-left align-middle font-semibold text-xs uppercase tracking-wider text-muted-foreground [&:has([role=checkbox])]:pr-0', props.class)">
    <slot />
  </th>
</template>
