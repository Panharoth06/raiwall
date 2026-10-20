<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

export interface BadgeProps {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline' | 'blue' | 'emerald' | 'amber' | 'rose'
  class?: HTMLAttributes['class']
}

const props = withDefaults(defineProps<BadgeProps>(), {
  variant: 'default',
})

const variantClasses: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'border-transparent bg-[#2574F5] text-white shadow-none',
  secondary: 'border-transparent bg-[#17223B] text-slate-200 shadow-none',
  destructive: 'border-transparent bg-red-600/80 text-white shadow-none',
  outline: 'border-[#2d3440] text-slate-300 shadow-none',
  blue: 'border-[#2574F5]/30 bg-[#2574F5]/10 text-[#38BDF8] shadow-none',
  emerald: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400 shadow-none',
  amber: 'border-amber-500/30 bg-amber-500/10 text-amber-400 shadow-none',
  rose: 'border-rose-500/30 bg-rose-500/10 text-rose-400 shadow-none',
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
