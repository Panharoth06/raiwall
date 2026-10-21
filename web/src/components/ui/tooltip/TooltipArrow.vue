<script setup lang="ts">
import { TooltipArrow, type TooltipArrowProps } from 'radix-vue'
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<TooltipArrowProps & { class?: HTMLAttributes['class'] }>()
</script>

<template>
  <TooltipArrow v-bind="props" :class="cn('fill-popover', props.class)" />
</template>
