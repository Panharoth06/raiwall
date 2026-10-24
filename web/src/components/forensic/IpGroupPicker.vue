<script setup lang="ts">
import { ref, watch } from 'vue';
import type { IPGroupOption } from '@/types/telemetry';

/** In-drawer control to append the offending client IP to a named BART IP group. */
const props = defineProps<{
  groups: IPGroupOption[];
  disabled?: boolean;
  status?: string;
}>();

const emit = defineEmits<{
  (e: 'add', groupId: string): void;
}>();

const selected = ref('');

watch(
  () => props.groups,
  (groups) => {
    if (!groups.some((g) => g.id === selected.value)) {
      selected.value = groups[0]?.id ?? '';
    }
  },
  { immediate: true }
);

function submit() {
  if (!selected.value || props.disabled) return;
  emit('add', selected.value);
}
</script>

<template>
  <div class="flex items-center gap-2">
    <select
      v-model="selected"
      data-testid="ipgroup-select"
      :disabled="disabled || groups.length === 0"
      class="h-8 px-2 text-xs bg-background border border-input rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
    >
      <option v-if="groups.length === 0" value="">No IP groups</option>
      <option v-for="group in groups" :key="group.id" :value="group.id">
        {{ group.name }}
      </option>
    </select>
    <button
      type="button"
      data-testid="add-to-ipgroup-btn"
      :disabled="disabled || groups.length === 0"
      class="px-3 py-1.5 text-xs font-medium text-foreground bg-muted hover:bg-muted/80 border border-border rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
      @click="submit"
    >
      Add to IP Group
    </button>
    <span v-if="status" class="text-[11px] text-muted-foreground">{{ status }}</span>
  </div>
</template>
