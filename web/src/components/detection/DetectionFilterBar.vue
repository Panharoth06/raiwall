<script setup lang="ts">
import type { RuleFacets, RuleFilters } from '@/api/detection';
import { Button } from '@/components/ui/button';
import { SearchInput } from '@/components/ui/search-input';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';

const props = defineProps<{
  facets: RuleFacets;
  filters: RuleFilters;
}>();

const emit = defineEmits<{
  'update:filters': [filters: RuleFilters];
}>();

const ALL = '__all__';

const set = (key: keyof RuleFilters, value: string) => {
  emit('update:filters', {
    ...props.filters,
    [key]: value === ALL ? '' : value,
  });
};

const clear = () => {
  emit('update:filters', { q: '', source: '', category: '', severity: '', enabled: '' });
};
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <SearchInput
      :model-value="filters.q"
      clearable
      placeholder="Search rule ID, name, category…"
      class="flex-1 sm:flex-initial sm:w-64 min-w-[200px]"
      input-class="h-8 text-xs"
      data-testid="rule-catalog-search"
      @update:model-value="(value) => set('q', String(value ?? ''))"
    />

    <div class="flex flex-wrap items-center gap-2 flex-1 sm:flex-initial">
      <Select :model-value="filters.source || ALL" @update:model-value="(value) => set('source', String(value))">
        <SelectTrigger class="h-8 w-full sm:w-36 text-xs bg-card border-border text-foreground" data-testid="rule-source-filter">
          <SelectValue />
        </SelectTrigger>
        <SelectContent class="border-border bg-popover text-popover-foreground">
          <SelectItem :value="ALL" class="text-xs">All sources</SelectItem>
          <SelectItem v-for="facet in facets.sources" :key="facet.value" :value="facet.value" class="text-xs">
            {{ facet.value }} ({{ facet.count }})
          </SelectItem>
        </SelectContent>
      </Select>

      <Select :model-value="filters.category || ALL" @update:model-value="(value) => set('category', String(value))">
        <SelectTrigger class="h-8 w-full sm:w-36 text-xs bg-card border-border text-foreground" data-testid="rule-category-filter">
          <SelectValue />
        </SelectTrigger>
        <SelectContent class="border-border bg-popover text-popover-foreground">
          <SelectItem :value="ALL" class="text-xs">All categories</SelectItem>
          <SelectItem v-for="facet in facets.categories" :key="facet.value" :value="facet.value" class="text-xs">
            {{ facet.value }} ({{ facet.count }})
          </SelectItem>
        </SelectContent>
      </Select>

      <Select :model-value="filters.severity || ALL" @update:model-value="(value) => set('severity', String(value))">
        <SelectTrigger class="h-8 w-full sm:w-32 text-xs bg-card border-border text-foreground" data-testid="rule-severity-filter">
          <SelectValue />
        </SelectTrigger>
        <SelectContent class="border-border bg-popover text-popover-foreground">
          <SelectItem :value="ALL" class="text-xs">All severities</SelectItem>
          <SelectItem v-for="facet in facets.severities" :key="facet.value" :value="facet.value" class="text-xs">
            {{ facet.value }} ({{ facet.count }})
          </SelectItem>
        </SelectContent>
      </Select>

      <Select :model-value="filters.enabled || ALL" @update:model-value="(value) => set('enabled', String(value))">
        <SelectTrigger class="h-8 w-full sm:w-28 text-xs bg-card border-border text-foreground" data-testid="rule-enabled-filter">
          <SelectValue />
        </SelectTrigger>
        <SelectContent class="border-border bg-popover text-popover-foreground">
          <SelectItem :value="ALL" class="text-xs">Any state</SelectItem>
          <SelectItem value="true" class="text-xs">Enabled</SelectItem>
          <SelectItem value="false" class="text-xs">Disabled</SelectItem>
        </SelectContent>
      </Select>

      <Button
        v-if="filters.q || filters.source || filters.category || filters.severity || filters.enabled"
        size="sm"
        variant="ghost"
        class="h-8 text-xs text-muted-foreground hover:text-foreground"
        @click="clear"
      >
        Clear filters
      </Button>
    </div>
  </div>
</template>
