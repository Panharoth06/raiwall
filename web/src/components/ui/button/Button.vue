<script setup lang="ts">
import { type HTMLAttributes } from 'vue'
import { Primitive, type PrimitiveProps } from 'radix-vue'
import { cn } from '@/lib/utils'

export interface ButtonProps extends PrimitiveProps {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link'
  size?: 'default' | 'sm' | 'lg' | 'icon'
  class?: HTMLAttributes['class']
  type?: 'button' | 'submit' | 'reset'
  disabled?: boolean
}

const props = withDefaults(defineProps<ButtonProps>(), {
  as: 'button',
  variant: 'default',
  size: 'default',
  type: 'button',
})

const variantClasses: Record<NonNullable<ButtonProps['variant']>, string> = {
  default: 'bg-primary hover:bg-primary/90 text-primary-foreground active:brightness-95 transition-colors shadow-none',
  secondary: 'bg-secondary hover:bg-secondary/80 text-secondary-foreground border border-border active:brightness-95 shadow-none',
  outline: 'border border-border hover:bg-muted text-foreground active:bg-muted/80 shadow-none',
  ghost: 'hover:bg-muted text-muted-foreground hover:text-foreground active:bg-muted/80 shadow-none',
  destructive: 'bg-destructive hover:bg-destructive/90 text-destructive-foreground active:brightness-95 shadow-none',
  link: 'text-primary underline-offset-4 hover:underline shadow-none',
}

const sizeClasses: Record<NonNullable<ButtonProps['size']>, string> = {
  default: 'h-9 px-4 py-2 text-xs',
  sm: 'h-8 rounded-md px-3 text-xs',
  lg: 'h-10 rounded-md px-8 text-sm',
  icon: 'h-9 w-9 p-0',
}
</script>

<template>
  <Primitive
    :as="as"
    :as-child="asChild"
    :type="as === 'button' ? type : undefined"
    :disabled="disabled"
    :class="
      cn(
        'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium select-none cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 shadow-none',
        variantClasses[props.variant || 'default'],
        sizeClasses[props.size || 'default'],
        props.class
      )
    "
  >
    <slot />
  </Primitive>
</template>
