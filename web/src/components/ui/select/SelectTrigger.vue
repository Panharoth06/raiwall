<script setup lang="ts">
import { SelectTrigger, type SelectTriggerProps, useForwardProps } from 'radix-vue'
import { ChevronDown } from 'lucide-vue-next'
import { type HTMLAttributes } from 'vue'

const props = defineProps<SelectTriggerProps & { class?: HTMLAttributes['class'] }>()
const forwarded = useForwardProps(props)
</script>

<template>
  <SelectTrigger
    v-bind="forwarded"
    :class="[
      'flex h-9 w-full items-center justify-between rounded-md border border-[#363D4C] bg-[#15181F] px-3 py-2 text-xs text-white placeholder:text-[#848D9C] focus:outline-none focus:ring-1 focus:ring-[#2574F5] disabled:cursor-not-allowed disabled:opacity-50 cursor-pointer',
      props.class
    ]"
  >
    <slot />
    <ChevronDown class="h-3.5 w-3.5 opacity-50 ml-2 shrink-0" />
  </SelectTrigger>
</template>
