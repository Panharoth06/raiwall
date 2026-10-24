<script setup lang="ts">
import { computed, useAttrs } from 'vue';
import { Search, X } from 'lucide-vue-next';
import { cn } from '@/lib/utils';

defineOptions({
  name: 'SearchInput',
  inheritAttrs: false,
});

const props = withDefaults(
  defineProps<{
    placeholder?: string;
    clearable?: boolean;
    disabled?: boolean;
    class?: string;
    inputClass?: string;
  }>(),
  {
    placeholder: 'Search…',
    clearable: false,
    disabled: false,
  }
);

const model = defineModel<string>({ default: '' });
const attrs = useAttrs();
const hasValue = computed(() => !!model.value);
</script>

<template>
  <div :class="cn('relative', props.class)">
    <Search
      aria-hidden="true"
      class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
    />
    <input
      v-bind="attrs"
      v-model="model"
      type="text"
      :disabled="disabled"
      :placeholder="placeholder"
      :class="
        cn(
          'h-8 w-full rounded-md border border-input bg-card pl-8 text-xs text-foreground placeholder:text-muted-foreground transition-colors focus-visible:border-primary focus-visible:outline-none focus-visible:ring-0 disabled:cursor-not-allowed disabled:opacity-50',
          clearable && hasValue ? 'pr-8' : 'pr-3',
          props.inputClass
        )
      "
    />
    <button
      v-if="clearable && hasValue"
      type="button"
      aria-label="Clear search"
      class="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
      @click="model = ''"
    >
      <X class="h-3 w-3" />
    </button>
  </div>
</template>
