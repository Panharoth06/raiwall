<script setup lang="ts">
import { PopoverContent, type PopoverContentEmits, type PopoverContentProps, PopoverPortal, useForwardPropsEmits } from 'radix-vue'
import { type HTMLAttributes } from 'vue'

defineOptions({
  inheritAttrs: false,
})

const props = withDefaults(
  defineProps<PopoverContentProps & { class?: HTMLAttributes['class'], to?: string | HTMLElement, disabled?: boolean }>(),
  {
    align: 'center',
    sideOffset: 4,
    disabled: true,
  }
)
const emits = defineEmits<PopoverContentEmits>()
const forwarded = useForwardPropsEmits(props, emits)
</script>

<template>
  <PopoverPortal :to="props.to" :disabled="props.disabled">
    <PopoverContent
      v-bind="{ ...forwarded, ...$attrs }"
      :class="[
        'z-50 w-72 rounded-md border border-border bg-popover p-4 text-popover-foreground shadow-xl outline-none',
        props.class
      ]"
    >
      <slot />
    </PopoverContent>
  </PopoverPortal>
</template>
