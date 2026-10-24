<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  semanticsApi,
  type InnerRule,
  type InnerRuleCategory,
} from '@/api/semantics';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Loader2, Search, ShieldCheck } from 'lucide-vue-next';

const rules = ref<InnerRule[]>([]);
const categories = ref<InnerRuleCategory[]>([]);
const loading = ref(true);
const error = ref('');
const search = ref('');
const activeCategory = ref('all');
const pending = ref<Set<string>>(new Set());

const loadRules = async () => {
  loading.value = true;
  error.value = '';
  try {
    const library = await semanticsApi.listInnerRules();
    rules.value = library.rules;
    categories.value = library.categories;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load inner rules';
  } finally {
    loading.value = false;
  }
};

const filteredRules = computed(() => {
  const query = search.value.trim().toLowerCase();
  return rules.value.filter((rule) => {
    if (activeCategory.value !== 'all' && rule.category !== activeCategory.value) return false;
    if (query && !`${rule.id} ${rule.name}`.toLowerCase().includes(query)) return false;
    return true;
  });
});

const enabledCount = computed(() => rules.value.filter((r) => r.enabled).length);

const toggleRule = async (rule: InnerRule, enabled: boolean) => {
  const previous = rule.enabled;
  rule.enabled = enabled;
  pending.value.add(rule.id);
  try {
    await semanticsApi.setInnerRuleEnabled(rule.id, enabled);
  } catch (e) {
    rule.enabled = previous;
    error.value = e instanceof Error ? e.message : 'Toggle failed';
  } finally {
    pending.value.delete(rule.id);
  }
};

const batchCategory = async (category: string, enabled: boolean) => {
  error.value = '';
  try {
    await semanticsApi.setInnerRuleCategoryEnabled(category, enabled);
    const affected = rules.value.filter((r) => r.category === category);
    for (const rule of affected) rule.enabled = enabled;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Batch action failed';
  }
};

const batchLibrary = async (enabled: boolean) => {
  error.value = '';
  try {
    for (const category of categories.value) {
      await semanticsApi.setInnerRuleCategoryEnabled(category.category, enabled);
    }
    for (const rule of rules.value) rule.enabled = enabled;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Batch action failed';
  }
};

const categoryLabel = (category: string) =>
  categories.value.find((c) => c.category === category)?.count ?? 0;

onMounted(loadRules);
</script>

<template>
  <div class="h-full flex flex-col space-y-3 p-6 bg-card text-card-foreground rounded-xl border border-border font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <ShieldCheck class="w-4 h-4 text-muted-foreground" />
          <span>CVE Virtual Patches — Inner Rules</span>
        </h1>
        <p class="text-xs text-muted-foreground mt-0.5" data-testid="rule-summary">
          {{ enabledCount }} of {{ rules.length }} signatures enabled — state changes are staged, apply via Config
        </p>
      </div>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="rules-error">{{ error }}</p>

    <!-- Toolbar -->
    <div class="flex items-center gap-2 shrink-0 flex-wrap">
      <div class="relative">
        <Search class="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <Input
          v-model="search"
          placeholder="Search rule ID or name…"
          class="h-7 w-56 pl-7 text-xs"
          data-testid="rule-search"
        />
      </div>
      <button
        type="button"
        class="rounded-md border px-2 py-1 text-[11px] font-mono transition-colors duration-150"
        :class="activeCategory === 'all' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'"
        data-testid="category-chip-all"
        @click="activeCategory = 'all'"
      >
        all ({{ rules.length }})
      </button>
      <button
        v-for="cat in categories"
        :key="cat.category"
        type="button"
        class="rounded-md border px-2 py-1 text-[11px] font-mono transition-colors duration-150"
        :class="activeCategory === cat.category ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'"
        :data-testid="`category-chip-${cat.category}`"
        @click="activeCategory = cat.category"
      >
        {{ cat.category }} ({{ cat.count }}){{ cat.disabled ? ` · ${cat.disabled} off` : '' }}
      </button>
      <span class="grow" />
      <Button
        size="sm"
        variant="outline"
        class="h-7 text-xs gap-1"
        data-testid="batch-enable-all"
        @click="batchLibrary(true)"
      >
        Enable All Rules
      </Button>
      <Button
        size="sm"
        variant="outline"
        class="h-7 text-xs gap-1 text-destructive hover:text-destructive"
        data-testid="batch-disable-all"
        @click="batchLibrary(false)"
      >
        Disable All Rules
      </Button>
    </div>

    <!-- Per-category batch for active filter -->
    <div v-if="activeCategory !== 'all'" class="flex items-center gap-2 shrink-0">
      <span class="text-[11px] text-muted-foreground">Batch manager for</span>
      <Badge variant="outline" class="font-mono text-[10px] tracking-normal">{{ activeCategory }}</Badge>
      <Button size="sm" variant="outline" class="h-7 text-xs gap-1" data-testid="batch-enable-category" @click="batchCategory(activeCategory, true)">
        Enable All {{ activeCategory }} Rules
      </Button>
      <Button size="sm" variant="outline" class="h-7 text-xs gap-1 text-destructive hover:text-destructive" data-testid="batch-disable-category" @click="batchCategory(activeCategory, false)">
        Disable All {{ activeCategory }} Rules
      </Button>
    </div>

    <!-- Skeletons -->
    <div v-if="loading" class="space-y-2 shrink-0" data-testid="rules-loading">
      <div v-for="n in 8" :key="n" class="h-8 rounded-md bg-muted/50 animate-pulse" />
    </div>

    <!-- Rules table -->
    <div v-else class="grow min-h-0 overflow-y-auto rounded-lg border border-border bg-card">
      <Table data-testid="inner-rules-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="w-56">Signature</TableHead>
            <TableHead>Detection</TableHead>
            <TableHead class="w-28">Category</TableHead>
            <TableHead class="w-24 text-right">Enabled</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
            v-for="rule in filteredRules"
            :key="rule.id"
            :data-testid="`rule-row-${rule.id}`"
          >
            <TableCell>
              <span class="font-mono text-[11px] text-primary">{{ rule.id }}</span>
            </TableCell>
            <TableCell class="text-foreground">{{ rule.name }}</TableCell>
            <TableCell>
              <span class="font-mono text-[10px] text-muted-foreground">{{ rule.category }} ({{ categoryLabel(rule.category) }})</span>
            </TableCell>
            <TableCell class="text-right">
              <div class="inline-flex items-center gap-2">
                <Loader2 v-if="pending.has(rule.id)" class="w-3 h-3 animate-spin text-muted-foreground" />
                <Switch
                  :checked="rule.enabled"
                  :data-testid="`rule-toggle-${rule.id}`"
                  @update:checked="(v) => toggleRule(rule, v)"
                />
              </div>
            </TableCell>
          </TableRow>
          <TableRow v-if="filteredRules.length === 0">
            <TableCell colspan="4" class="py-6 text-center text-muted-foreground" data-testid="rules-empty">
              No signatures match the current filter.
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>
  </div>
</template>
