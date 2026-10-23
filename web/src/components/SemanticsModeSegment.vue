<script setup lang="ts">
import type { ModuleMode } from '@/api/semantics';

const props = defineProps<{
  modelValue: ModuleMode | 'inherit';
  /** Render an "Inherit" option (per-site override rows follow the global matrix). */
  inherit?: boolean;
  disabled?: boolean;
}>();

const emit = defineEmits<{ (e: 'update:modelValue', value: ModuleMode | 'inherit'): void }>();

const MODES: { value: ModuleMode | 'inherit'; label: string; title: string }[] = [];
if (props.inherit) {
  MODES.push({ value: 'inherit', label: 'Inherit', title: 'Follow the global matrix mode' });
}
MODES.push(
  { value: 'disabled', label: 'Disabled', title: 'Module switched off, never evaluates' },
  { value: 'audit', label: 'Audit', title: 'Record findings without blocking' },
  { value: 'balance', label: 'Balance', title: 'Block strong signals only (default)' },
  { value: 'strict', label: 'Strict', title: 'Block strong and weak signals' },
);

const handleSelect = (value: ModuleMode | 'inherit') => {
  if (!props.disabled) emit('update:modelValue', value);
};
</script>

<template>
  <div
    class="inline-flex items-center rounded-md border border-border bg-muted/40 p-0.5"
    role="radiogroup"
    data-testid="mode-segment"
  >
    <button
      v-for="mode in MODES"
      :key="mode.value"
      type="button"
      role="radio"
      :aria-checked="props.modelValue === mode.value"
      :title="mode.title"
      :data-testid="`mode-${mode.value}`"
      class="rounded px-2 py-0.5 text-[11px] font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      :class="
        props.modelValue === mode.value
          ? 'bg-primary text-primary-foreground'
          : 'text-muted-foreground hover:text-foreground'
      "
      :disabled="props.disabled"
      @click="handleSelect(mode.value)"
    >
      {{ mode.label }}
    </button>
  </div>
</template>
