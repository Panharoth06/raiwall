<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

export interface BadgeProps {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline' | 'threat' | 'success' | 'warning' | 'info' | 'blue' | 'emerald' | 'amber' | 'rose'
  class?: HTMLAttributes['class']
}

const props = withDefaults(defineProps<BadgeProps>(), {
  variant: 'default',
})

const variantClasses: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'border-transparent bg-primary text-primary-foreground shadow-none',
  secondary: 'border-transparent bg-secondary text-secondary-foreground shadow-none',
  destructive: 'border-transparent bg-destructive text-destructive-foreground shadow-none',
  outline: 'border-border text-foreground shadow-none',
  threat: 'border-threat/30 bg-threat/10 text-threat shadow-none',
  success: 'border-success/30 bg-success/10 text-success shadow-none',
  warning: 'border-warning/30 bg-warning/10 text-warning shadow-none',
  info: 'border-info/30 bg-info/10 text-info shadow-none',
  blue: 'border-info/30 bg-info/10 text-info shadow-none',
  emerald: 'border-success/30 bg-success/10 text-success shadow-none',
  amber: 'border-warning/30 bg-warning/10 text-warning shadow-none',
  rose: 'border-threat/30 bg-threat/10 text-threat shadow-none',
}
</script>

<template>
  <span
    :class="
      cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium font-sans transition-colors shadow-none',
        variantClasses[props.variant || 'default'],
        props.class
      )
    "
  >
    <slot />
  </span>
</template>
