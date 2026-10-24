<script setup lang="ts">
import { ref, watch } from 'vue';
import type { IPGroupOption } from '@/types/telemetry';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';

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
    <div class="w-40 relative">
      <Select
        v-model="selected"
        :disabled="disabled || groups.length === 0"
      >
        <SelectTrigger class="h-8 text-xs bg-background border-input text-foreground">
          <SelectValue :placeholder="groups.length === 0 ? 'No IP groups' : 'Select IP group'" />
        </SelectTrigger>
        <SelectContent class="border-border bg-popover text-popover-foreground">
          <SelectItem
            v-for="group in groups"
            :key="group.id"
            :value="group.id"
            class="text-xs"
          >
            {{ group.name }}
          </SelectItem>
        </SelectContent>
      </Select>
      <select
        v-model="selected"
        data-testid="ipgroup-select"
        class="sr-only"
        tabindex="-1"
        aria-hidden="true"
        :disabled="disabled || groups.length === 0"
      >
        <option v-if="groups.length === 0" value="">No IP groups</option>
        <option v-for="group in groups" :key="group.id" :value="group.id">
          {{ group.name }}
        </option>
      </select>
    </div>
    <button
      type="button"
      data-testid="add-to-ipgroup-btn"
      :disabled="disabled || groups.length === 0"
      class="px-3 py-1.5 text-xs font-medium text-foreground bg-muted hover:bg-muted/80 border border-border rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shrink-0"
      @click="submit"
    >
      Add to IP Group
    </button>
    <span v-if="status" class="text-[11px] text-muted-foreground">{{ status }}</span>
  </div>
</template>
