<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Popover, PopoverTrigger, PopoverContent } from '@/components/ui/popover';
import { Button } from '@/components/ui/button';
import { Calendar as CalendarIcon, ChevronLeft, ChevronRight, X } from 'lucide-vue-next';
import { cn } from '@/lib/utils';

const props = withDefaults(
  defineProps<{
    modelValue?: string;
    placeholder?: string;
    disabled?: boolean;
    class?: string;
  }>(),
  {
    modelValue: '',
    placeholder: 'Pick a date',
    disabled: false,
    class: '',
  }
);

const emit = defineEmits<{
  (e: 'update:modelValue', val: string): void;
}>();

const open = ref(false);

const today = new Date();
const currentYear = ref(today.getFullYear());
const currentMonth = ref(today.getMonth()); // 0-indexed

// Sync initial month/year from modelValue if provided
watch(
  () => props.modelValue,
  (val) => {
    if (val) {
      const parsed = new Date(val);
      if (!isNaN(parsed.getTime())) {
        currentYear.value = parsed.getFullYear();
        currentMonth.value = parsed.getMonth();
      }
    }
  },
  { immediate: true }
);

const monthNames = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'
];

const currentMonthLabel = computed(() => {
  return `${monthNames[currentMonth.value]} ${currentYear.value}`;
});

const dayLabels = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];

interface CalendarDay {
  day: number;
  monthOffset: number; // -1 = prev month, 0 = current, 1 = next
  dateString: string;
  isToday: boolean;
  isSelected: boolean;
}

const calendarDays = computed(() => {
  const days: CalendarDay[] = [];
  const year = currentYear.value;
  const month = currentMonth.value;

  const firstDayOfWeek = new Date(year, month, 1).getDay();
  const daysInCurrentMonth = new Date(year, month + 1, 0).getDate();
  const daysInPrevMonth = new Date(year, month, 0).getDate();

  const pad = (n: number) => (n < 10 ? `0${n}` : `${n}`);
  const todayStr = `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;

  // Previous month padding
  for (let i = firstDayOfWeek - 1; i >= 0; i--) {
    const d = daysInPrevMonth - i;
    const prevMonth = month === 0 ? 11 : month - 1;
    const prevYear = month === 0 ? year - 1 : year;
    const dateStr = `${prevYear}-${pad(prevMonth + 1)}-${pad(d)}`;
    days.push({
      day: d,
      monthOffset: -1,
      dateString: dateStr,
      isToday: dateStr === todayStr,
      isSelected: dateStr === props.modelValue,
    });
  }

  // Current month days
  for (let d = 1; d <= daysInCurrentMonth; d++) {
    const dateStr = `${year}-${pad(month + 1)}-${pad(d)}`;
    days.push({
      day: d,
      monthOffset: 0,
      dateString: dateStr,
      isToday: dateStr === todayStr,
      isSelected: dateStr === props.modelValue,
    });
  }

  // Next month padding to complete 35 or 42 grid cells
  const remaining = 35 - days.length >= 0 ? 35 - days.length : 42 - days.length;
  for (let d = 1; d <= remaining; d++) {
    const nextMonth = month === 11 ? 0 : month + 1;
    const nextYear = month === 11 ? year + 1 : year;
    const dateStr = `${nextYear}-${pad(nextMonth + 1)}-${pad(d)}`;
    days.push({
      day: d,
      monthOffset: 1,
      dateString: dateStr,
      isToday: dateStr === todayStr,
      isSelected: dateStr === props.modelValue,
    });
  }

  return days;
});

const prevMonth = () => {
  if (currentMonth.value === 0) {
    currentMonth.value = 11;
    currentYear.value--;
  } else {
    currentMonth.value--;
  }
};

const nextMonth = () => {
  if (currentMonth.value === 11) {
    currentMonth.value = 0;
    currentYear.value++;
  } else {
    currentMonth.value++;
  }
};

const selectDay = (item: CalendarDay) => {
  emit('update:modelValue', item.dateString);
  open.value = false;
};

const selectToday = () => {
  const pad = (n: number) => (n < 10 ? `0${n}` : `${n}`);
  const todayStr = `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;
  emit('update:modelValue', todayStr);
  open.value = false;
};

const clearDate = (e?: MouseEvent) => {
  if (e) e.stopPropagation();
  emit('update:modelValue', '');
  open.value = false;
};
</script>

<template>
  <Popover v-model:open="open">
    <PopoverTrigger as-child>
      <button
        type="button"
        :disabled="disabled"
        :class="
          cn(
            'flex h-9 w-44 items-center justify-between rounded-md border border-input bg-card px-3 py-1 text-xs shadow-none hover:bg-muted/30 focus-visible:outline-none focus-visible:border-primary focus-visible:ring-1 focus-visible:ring-ring transition-colors cursor-pointer select-none text-left',
            !modelValue && 'text-muted-foreground',
            disabled && 'cursor-not-allowed opacity-50',
            props.class
          )
        "
      >
        <span class="truncate font-mono font-normal">
          {{ modelValue || placeholder }}
        </span>

        <div class="flex items-center gap-1 ml-1.5 shrink-0">
          <X
            v-if="modelValue"
            class="w-3.5 h-3.5 text-muted-foreground hover:text-foreground"
            @click="clearDate"
          />
          <CalendarIcon class="w-3.5 h-3.5 text-muted-foreground" />
        </div>
      </button>
    </PopoverTrigger>

    <PopoverContent class="w-64 p-3 bg-card text-foreground border border-border shadow-md rounded-lg">
      <!-- Calendar Header -->
      <div class="flex items-center justify-between pb-2 mb-2 border-b border-border/60">
        <Button
          variant="ghost"
          size="icon"
          class="h-6 w-6 text-muted-foreground hover:text-foreground"
          @click="prevMonth"
        >
          <ChevronLeft class="h-3.5 w-3.5" />
        </Button>

        <span class="text-xs font-semibold text-foreground">
          {{ currentMonthLabel }}
        </span>

        <Button
          variant="ghost"
          size="icon"
          class="h-6 w-6 text-muted-foreground hover:text-foreground"
          @click="nextMonth"
        >
          <ChevronRight class="h-3.5 w-3.5" />
        </Button>
      </div>

      <!-- Days of Week Header -->
      <div class="grid grid-cols-7 gap-1 text-center mb-1">
        <span
          v-for="d in dayLabels"
          :key="d"
          class="text-[10px] font-medium text-muted-foreground py-0.5"
        >
          {{ d }}
        </span>
      </div>

      <!-- Days Grid -->
      <div class="grid grid-cols-7 gap-1">
        <button
          v-for="item in calendarDays"
          :key="item.dateString"
          type="button"
          :class="[
            'h-7 w-7 text-xs rounded-md flex items-center justify-center font-mono transition-colors cursor-pointer',
            item.monthOffset !== 0 ? 'text-muted-foreground/30 hover:bg-muted/30' : 'text-foreground hover:bg-muted',
            item.isToday && !item.isSelected ? 'ring-1 ring-primary font-semibold' : '',
            item.isSelected ? 'bg-primary text-primary-foreground font-semibold hover:bg-primary' : '',
          ]"
          @click="selectDay(item)"
        >
          {{ item.day }}
        </button>
      </div>

      <!-- Quick Action Buttons -->
      <div class="flex items-center justify-between pt-2 mt-2 border-t border-border/60 text-xs">
        <Button
          variant="ghost"
          size="sm"
          class="h-6 px-2 text-[11px] text-muted-foreground hover:text-foreground"
          @click="clearDate"
        >
          Clear
        </Button>
        <Button
          variant="ghost"
          size="sm"
          class="h-6 px-2 text-[11px] font-medium text-primary hover:text-primary hover:bg-primary/10"
          @click="selectToday"
        >
          Today
        </Button>
      </div>
    </PopoverContent>
  </Popover>
</template>
