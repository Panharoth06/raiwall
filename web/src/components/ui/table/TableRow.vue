<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <tr :class="cn('border-b border-[#2d3440]/60 transition-colors hover:bg-[#17223B]/30 data-[state=selected]:bg-[#17223B]/50', props.class)">
    <slot />
  </tr>
</template>
