<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { ChevronRight } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <li
    role="presentation"
    aria-hidden="true"
    :class="cn('[&>svg]:w-3.5 [&>svg]:h-3.5 text-muted-foreground/60', props.class)"
  >
    <slot>
      <ChevronRight class="w-3.5 h-3.5" />
    </slot>
  </li>
</template>
