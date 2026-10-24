<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  CONTINENT_DATA,
  ALL_COUNTRIES,
  getCountryName,
  type ContinentGroup,
} from './geoData';
import { Search, Globe2, ChevronRight, X } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    modelValue: string;
    placeholder?: string;
  }>(),
  {
    placeholder: 'Select country / region...',
  }
);

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void;
}>();

const isOpen = ref(false);
const searchQuery = ref('');
const activeContinentId = ref<string>('asia');

const selectedCodes = computed<Set<string>>(() => {
  if (!props.modelValue) return new Set();
  const codes = props.modelValue
    .split(',')
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  return new Set(codes);
});

const updateSelected = (newSet: Set<string>) => {
  const arr = Array.from(newSet).sort();
  emit('update:modelValue', arr.join(', '));
};

const toggleCountry = (code: string) => {
  const next = new Set(selectedCodes.value);
  if (next.has(code)) {
    next.delete(code);
  } else {
    next.add(code);
  }
  updateSelected(next);
};

const activeContinent = computed<ContinentGroup>(() => {
  return (
    CONTINENT_DATA.find((c) => c.id === activeContinentId.value) ||
    CONTINENT_DATA[0]
  );
});

const isContinentFullySelected = (c: ContinentGroup): boolean => {
  if (c.countries.length === 0) return false;
  return c.countries.every((item) => selectedCodes.value.has(item.code));
};

const isContinentPartiallySelected = (c: ContinentGroup): boolean => {
  const count = c.countries.filter((item) => selectedCodes.value.has(item.code)).length;
  return count > 0 && count < c.countries.length;
};

const toggleContinent = (c: ContinentGroup) => {
  const next = new Set(selectedCodes.value);
  const fully = isContinentFullySelected(c);
  if (fully) {
    c.countries.forEach((item) => next.delete(item.code));
  } else {
    c.countries.forEach((item) => next.add(item.code));
  }
  updateSelected(next);
};

const isAllFullySelected = computed(() => {
  return ALL_COUNTRIES.every((item) => selectedCodes.value.has(item.code));
});

const toggleAll = () => {
  if (isAllFullySelected.value) {
    updateSelected(new Set());
  } else {
    updateSelected(new Set(ALL_COUNTRIES.map((c) => c.code)));
  }
};

const filteredCountries = computed(() => {
  const q = searchQuery.value.trim().toLowerCase();
  if (!q) return [];
  return ALL_COUNTRIES.filter(
    (c) => c.name.toLowerCase().includes(q) || c.code.toLowerCase().includes(q)
  );
});

const displayLabel = computed(() => {
  const count = selectedCodes.value.size;
  if (count === 0) return props.placeholder;
  if (count === 1) {
    const code = Array.from(selectedCodes.value)[0];
    return `${getCountryName(code)} (${code})`;
  }
  if (count <= 3) {
    return Array.from(selectedCodes.value).join(', ');
  }
  return `${count} countries selected`;
});

const clearSelection = (e: MouseEvent) => {
  e.stopPropagation();
  updateSelected(new Set());
};
</script>

<template>
  <div class="relative w-full">
    <!-- Trigger Button -->
    <button
      type="button"
      @click="isOpen = !isOpen"
      :class="[
        'w-full h-9 px-3 rounded-md border text-left text-xs flex items-center justify-between gap-1.5 transition-colors cursor-pointer',
        selectedCodes.size > 0
          ? 'border-primary/60 bg-primary/5 text-foreground'
          : 'border-input bg-card text-muted-foreground hover:border-primary/40'
      ]"
    >
      <div class="flex items-center gap-1.5 truncate">
        <Globe2 class="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        <span class="truncate font-mono text-[11px]">{{ displayLabel }}</span>
      </div>

      <div class="flex items-center gap-1 shrink-0">
        <button
          v-if="selectedCodes.size > 0"
          type="button"
          @click="clearSelection"
          class="p-0.5 text-muted-foreground hover:text-threat rounded cursor-pointer"
          title="Clear country selection"
        >
          <X class="w-3 h-3" />
        </button>
        <ChevronRight
          class="w-3.5 h-3.5 text-muted-foreground transition-transform"
          :class="isOpen ? 'rotate-90' : ''"
        />
      </div>
    </button>

    <!-- Backdrop Click to Close -->
    <div
      v-if="isOpen"
      class="fixed inset-0 z-40"
      @click="isOpen = false"
    />

    <!-- Popover Panel -->
    <div
      v-if="isOpen"
      class="absolute left-0 top-10 z-50 w-full sm:w-[480px] rounded-lg border border-border bg-card text-card-foreground shadow-xl overflow-hidden font-sans"
    >
      <!-- Search Bar -->
      <div class="p-2 border-b border-border bg-card flex items-center gap-2">
        <Search class="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search country or code (e.g. United States, CN)..."
          class="w-full bg-transparent text-xs text-foreground placeholder:text-muted-foreground outline-none"
        />
        <button
          v-if="searchQuery"
          type="button"
          @click="searchQuery = ''"
          class="text-muted-foreground hover:text-foreground text-xs p-1"
        >
          <X class="w-3 h-3" />
        </button>
      </div>

      <!-- Searched Flat List View -->
      <div v-if="searchQuery" class="max-h-60 overflow-y-auto p-1.5 space-y-0.5">
        <div
          v-for="item in filteredCountries"
          :key="item.code"
          @click="toggleCountry(item.code)"
          class="flex items-center gap-2 px-2.5 py-1.5 rounded hover:bg-muted/60 cursor-pointer text-xs"
        >
          <input
            type="checkbox"
            :checked="selectedCodes.has(item.code)"
            class="rounded border-border text-primary focus:ring-primary w-3.5 h-3.5 cursor-pointer"
            @click.stop="toggleCountry(item.code)"
          />
          <span class="font-mono text-[11px] text-muted-foreground w-7">{{ item.code }}</span>
          <span class="text-foreground truncate">{{ item.name }}</span>
        </div>
        <div v-if="filteredCountries.length === 0" class="p-4 text-center text-xs text-muted-foreground">
          No matching countries found.
        </div>
      </div>

      <!-- Cascaded 2-Column View (Continents -> Countries) -->
      <div v-else class="grid grid-cols-5 h-64 border-b border-border">
        <!-- Continents Left Column -->
        <div class="col-span-2 border-r border-border overflow-y-auto bg-muted/20 p-1 space-y-0.5">
          <!-- All Option -->
          <div
            @click="activeContinentId = 'all'"
            :class="[
              'flex items-center justify-between px-2 py-1.5 rounded text-xs cursor-pointer transition-colors',
              activeContinentId === 'all'
                ? 'bg-primary/10 text-primary font-semibold'
                : 'text-foreground hover:bg-muted/50'
            ]"
          >
            <div class="flex items-center gap-1.5 min-w-0">
              <input
                type="checkbox"
                :checked="isAllFullySelected"
                class="rounded border-border text-primary focus:ring-primary w-3.5 h-3.5 cursor-pointer"
                @click.stop="toggleAll"
              />
              <span class="truncate">All</span>
            </div>
            <ChevronRight class="w-3 h-3 text-muted-foreground shrink-0" />
          </div>

          <!-- Individual Continents -->
          <div
            v-for="grp in CONTINENT_DATA"
            :key="grp.id"
            @click="activeContinentId = grp.id"
            :class="[
              'flex items-center justify-between px-2 py-1.5 rounded text-xs cursor-pointer transition-colors',
              activeContinentId === grp.id
                ? 'bg-primary/10 text-primary font-semibold'
                : 'text-foreground hover:bg-muted/50'
            ]"
          >
            <div class="flex items-center gap-1.5 min-w-0">
              <input
                type="checkbox"
                :checked="isContinentFullySelected(grp)"
                :indeterminate="isContinentPartiallySelected(grp)"
                class="rounded border-border text-primary focus:ring-primary w-3.5 h-3.5 cursor-pointer"
                @click.stop="toggleContinent(grp)"
              />
              <span class="truncate">{{ grp.name }}</span>
            </div>
            <ChevronRight class="w-3 h-3 text-muted-foreground shrink-0" />
          </div>
        </div>

        <!-- Countries Right Column -->
        <div class="col-span-3 overflow-y-auto p-1 space-y-0.5 bg-card">
          <div
            v-for="item in (activeContinentId === 'all' ? ALL_COUNTRIES : activeContinent.countries)"
            :key="item.code"
            @click="toggleCountry(item.code)"
            class="flex items-center gap-2 px-2 py-1 rounded hover:bg-muted/60 cursor-pointer text-xs"
          >
            <input
              type="checkbox"
              :checked="selectedCodes.has(item.code)"
              class="rounded border-border text-primary focus:ring-primary w-3.5 h-3.5 cursor-pointer"
              @click.stop="toggleCountry(item.code)"
            />
            <span class="font-mono text-[11px] text-muted-foreground w-6">{{ item.code }}</span>
            <span class="text-foreground truncate">{{ item.name }}</span>
          </div>
        </div>
      </div>

      <!-- Footer Bar -->
      <div class="p-2 bg-muted/30 flex items-center justify-between text-xs">
        <span class="text-[11px] font-mono text-muted-foreground">
          Selected: <strong class="text-foreground">{{ selectedCodes.size }}</strong> countries
        </span>
        <button
          type="button"
          @click="isOpen = false"
          class="px-2.5 py-1 text-xs font-semibold rounded bg-primary text-primary-foreground hover:bg-primary/90 cursor-pointer"
        >
          Done
        </button>
      </div>
    </div>
  </div>
</template>
