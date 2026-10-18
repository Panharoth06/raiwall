<script setup lang="ts">
import { SwitchRoot, SwitchThumb, type SwitchRootEmits, type SwitchRootProps, useForwardPropsEmits } from 'radix-vue'
import { type HTMLAttributes } from 'vue'

const props = defineProps<SwitchRootProps & { class?: HTMLAttributes['class'] }>()
const emits = defineEmits<SwitchRootEmits>()
const forwarded = useForwardPropsEmits(props, emits)
</script>

<template>
  <SwitchRoot
    v-bind="forwarded"
    :class="[
      'peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#2574F5] focus-visible:ring-offset-2 focus-visible:ring-offset-[#1E222A] disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-[#2574F5] data-[state=unchecked]:bg-[#2A303C]',
      props.class
    ]"
  >
    <SwitchThumb
      :class="[
        'pointer-events-none block h-4 w-4 rounded-full bg-white shadow-lg ring-0 transition-transform data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0'
      ]"
    />
  </SwitchRoot>
</template>
