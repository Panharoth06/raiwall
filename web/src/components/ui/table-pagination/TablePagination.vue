<script setup lang="ts">
import { computed } from 'vue';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ChevronLeft, ChevronRight } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    page?: number;
    pageSize?: number;
    total: number;
    pageSizeOptions?: number[];
    itemLabel?: string;
    disabled?: boolean;
    prevTestId?: string;
    nextTestId?: string;
  }>(),
  {
    page: 1,
    pageSize: 20,
    pageSizeOptions: () => [10, 20, 50, 100],
    itemLabel: 'records',
    disabled: false,
    prevTestId: 'pagination-prev-btn',
    nextTestId: 'pagination-next-btn',
  }
);

const emit = defineEmits<{
  (e: 'update:page', value: number): void;
  (e: 'update:pageSize', value: number): void;
  (e: 'change', payload: { page: number; pageSize: number }): void;
}>();

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)));
const startItem = computed(() => (props.total > 0 ? (props.page - 1) * props.pageSize + 1 : 0));
const endItem = computed(() => Math.min(props.page * props.pageSize, props.total));

const goToPage = (newPage: number) => {
  if (newPage < 1 || newPage > totalPages.value || props.disabled) return;
  emit('update:page', newPage);
  emit('change', { page: newPage, pageSize: props.pageSize });
};

const onPageSizeChange = (val: string) => {
  const newSize = parseInt(val, 10);
  if (isNaN(newSize) || newSize === props.pageSize) return;
  emit('update:pageSize', newSize);
  emit('update:page', 1);
  emit('change', { page: 1, pageSize: newSize });
};
</script>

<template>
  <div
    class="flex items-center justify-between gap-3 px-4 py-2.5 border-t border-border bg-card text-xs text-muted-foreground font-sans flex-wrap shrink-0 select-none"
    data-testid="table-pagination"
  >
    <!-- Left: Showing X to Y of Z items -->
    <div class="flex items-center gap-1.5 font-sans">
      <span>Showing</span>
      <span class="font-mono text-foreground font-semibold">{{ startItem }}</span>
      <span>to</span>
      <span class="font-mono text-foreground font-semibold">{{ endItem }}</span>
      <span>of</span>
      <span class="font-mono text-foreground font-semibold">{{ total }}</span>
      <span>{{ itemLabel }}</span>
    </div>

    <!-- Right: Page size selector + Page navigation buttons -->
    <div class="flex items-center gap-3 ml-auto flex-wrap">
      <!-- Records Per Page Selector -->
      <div class="flex items-center gap-1.5">
        <span class="text-xs text-muted-foreground whitespace-nowrap">Show:</span>
        <Select
          :model-value="String(pageSize)"
          :disabled="disabled"
          @update:model-value="onPageSizeChange"
        >
          <SelectTrigger
            class="h-7 w-[72px] text-xs bg-background border-border text-foreground font-mono"
            data-testid="pagination-page-size-trigger"
          >
            <SelectValue :placeholder="String(pageSize)" />
          </SelectTrigger>
          <SelectContent :disabled="true" class="bg-popover text-popover-foreground border-border min-w-[72px] z-50">
            <SelectItem
              v-for="opt in pageSizeOptions"
              :key="opt"
              :value="String(opt)"
              class="text-xs font-mono"
              :data-testid="`page-size-opt-${opt}`"
            >
              {{ opt }}
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      <!-- Previous / Next Controls -->
      <div class="flex items-center gap-1">
        <Button
          variant="outline"
          size="sm"
          class="h-7 px-2.5 text-xs gap-1 border-border bg-muted/50 hover:bg-muted"
          :disabled="page <= 1 || disabled"
          :data-testid="prevTestId"
          @click="goToPage(page - 1)"
        >
          <ChevronLeft class="w-3.5 h-3.5" />
          <span class="hidden sm:inline">Previous</span>
        </Button>

        <span class="px-2 font-mono text-foreground font-medium text-xs">
          Page {{ page }} / {{ totalPages }}
        </span>

        <Button
          variant="outline"
          size="sm"
          class="h-7 px-2.5 text-xs gap-1 border-border bg-muted/50 hover:bg-muted"
          :disabled="page >= totalPages || disabled"
          :data-testid="nextTestId"
          @click="goToPage(page + 1)"
        >
          <span class="hidden sm:inline">Next</span>
          <ChevronRight class="w-3.5 h-3.5" />
        </Button>
      </div>
    </div>
  </div>
</template>
