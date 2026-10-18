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
        'z-50 w-72 rounded-md border border-[#363D4C] bg-[#1E222A] p-4 text-white shadow-[0_12px_28px_rgba(0,0,0,0.7)] outline-none',
        props.class
      ]"
    >
      <slot />
    </PopoverContent>
  </PopoverPortal>
</template>
