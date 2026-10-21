<script setup lang="ts">
import { SelectContent, type SelectContentEmits, type SelectContentProps, SelectPortal, SelectViewport, useForwardPropsEmits } from 'radix-vue'
import { type HTMLAttributes } from 'vue'

defineOptions({
  inheritAttrs: false,
})

const props = withDefaults(
  defineProps<SelectContentProps & { class?: HTMLAttributes['class'], to?: string | HTMLElement, disabled?: boolean }>(),
  {
    position: 'popper',
    sideOffset: 4,
    disabled: true,
  }
)
const emits = defineEmits<SelectContentEmits>()
const forwarded = useForwardPropsEmits(props, emits)
</script>

<template>
  <SelectPortal :to="props.to" :disabled="props.disabled">
    <SelectContent
      v-bind="{ ...forwarded, ...$attrs }"
      :class="[
        'relative z-50 max-h-96 min-w-[8rem] overflow-hidden rounded-md border border-border bg-popover text-popover-foreground shadow-xl',
        props.class
      ]"
    >
      <SelectViewport class="p-1">
        <slot />
      </SelectViewport>
    </SelectContent>
  </SelectPortal>
</template>
