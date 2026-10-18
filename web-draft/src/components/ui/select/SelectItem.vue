<script setup lang="ts">
import { SelectItem, type SelectItemProps, SelectItemText, SelectItemIndicator, useForwardProps } from 'radix-vue'
import { Check } from 'lucide-vue-next'
import { type HTMLAttributes } from 'vue'

const props = defineProps<SelectItemProps & { class?: HTMLAttributes['class'] }>()
const forwarded = useForwardProps(props)
</script>

<template>
  <SelectItem
    v-bind="forwarded"
    :class="[
      'relative flex w-full cursor-pointer select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-xs text-white outline-none focus:bg-[#2A303C] focus:text-white data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
      props.class
    ]"
  >
    <span class="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
      <SelectItemIndicator>
        <Check class="h-4 w-4 text-[#10B981]" />
      </SelectItemIndicator>
    </span>
    <SelectItemText>
      <slot />
    </SelectItemText>
  </SelectItem>
</template>
