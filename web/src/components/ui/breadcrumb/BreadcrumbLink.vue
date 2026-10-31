<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  href?: string
  as?: string
  class?: HTMLAttributes['class']
}>()

const emit = defineEmits<{
  (e: 'click', event: MouseEvent): void
}>()
</script>

<template>
  <component
    :is="props.as || (props.href ? 'a' : 'span')"
    :href="props.href"
    :class="
      cn(
        'transition-colors hover:text-foreground cursor-pointer text-muted-foreground',
        props.class
      )
    "
    @click="emit('click', $event)"
  >
    <slot />
  </component>
</template>
