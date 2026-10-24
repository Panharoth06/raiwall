<script setup lang="ts">
import { type HTMLAttributes, useAttrs } from 'vue'
import { cn } from '@/lib/utils'

defineOptions({ inheritAttrs: false })

const props = defineProps<{
  class?: HTMLAttributes['class']
  containerClass?: HTMLAttributes['class']
}>()

const attrs = useAttrs()
</script>

<template>
  <div :class="cn('relative w-full overflow-auto', props.containerClass)">
    <table
      v-bind="attrs"
      :class="cn('w-full caption-bottom border-separate border-spacing-0 text-xs text-foreground font-sans', props.class)"
    >
      <slot />
    </table>
  </div>
</template>
