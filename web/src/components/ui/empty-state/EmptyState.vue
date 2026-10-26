<script setup lang="ts">
import { type Component, type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  icon?: Component
  title: string
  description?: string
  class?: HTMLAttributes['class']
}>()
</script>

<template>
  <div
    :class="
      cn(
        'flex flex-col items-center justify-start pt-8 pb-10 px-4 text-center select-none font-sans',
        props.class
      )
    "
  >
    <div
      v-if="icon"
      class="w-10 h-10 rounded-lg bg-muted text-muted-foreground flex items-center justify-center mb-3"
    >
      <component :is="icon" class="w-5 h-5 text-muted-foreground" />
    </div>
    <h3 class="text-base font-semibold text-foreground tracking-tight">
      {{ title }}
    </h3>
    <p v-if="description" class="text-sm text-muted-foreground mt-1 max-w-sm leading-relaxed">
      {{ description }}
    </p>
    <div v-if="$slots.default" class="mt-4 flex items-center gap-2">
      <slot />
    </div>
  </div>
</template>
