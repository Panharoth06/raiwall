<script setup lang="ts">
import { computed } from 'vue';
import type { DetectionRule } from '@/api/detection';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Loader2 } from 'lucide-vue-next';

const props = defineProps<{
  rules: DetectionRule[];
  pending: Set<string>;
  canEdit: boolean;
  selected: Set<string>;
}>();

const emit = defineEmits<{
  select: [id: string, checked: boolean];
  selectAll: [checked: boolean];
  toggle: [rule: DetectionRule, enabled: boolean];
  action: [rule: DetectionRule, action: string];
  open: [rule: DetectionRule];
}>();

const allSelected = computed(
  () => props.rules.length > 0 && props.rules.every((rule) => props.selected.has(rule.id))
);

const actionOptions = [
  { value: 'inherit', label: 'Inherit' },
  { value: 'block', label: 'Block' },
  { value: 'alert', label: 'Alert' },
  { value: 'off', label: 'Off' },
];

const severityClass = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'border-threat/30 bg-threat/10 text-threat';
    case 'high':
      return 'border-warning/30 bg-warning/10 text-warning';
    case 'medium':
      return 'border-info/30 bg-info/10 text-info';
    default:
      return 'border-border bg-muted text-muted-foreground';
  }
};

const sourceBadgeText = (rule: DetectionRule): string => {
  if (rule.source === 'builtin' || rule.pack_name?.includes('Raiwall Core')) {
    return 'Core CVE';
  }
  if (rule.source === 'crs' || rule.pack_name?.includes('OWASP CRS') || rule.pack_name?.includes('CRS')) {
    return 'OWASP CRS';
  }
  if (rule.pack_name) {
    return rule.pack_name.replace(/\s*\([^)]*\)/g, '').trim();
  }
  return rule.source || 'Custom';
};

const formatRuleName = (name: string): string => {
  if (!name) return '—';
  return name
    .replace(/\s*\(Total Score:\s*%\{[^}]+\}\)/gi, '')
    .replace(/\s*%\{[^}]+\}/gi, '')
    .trim();
};
</script>

<template>
  <Table data-testid="rule-catalog-table" container-class="overflow-x-auto min-w-full">
    <TableHeader class="sticky top-0 z-10 bg-muted/95 backdrop-blur-sm border-b border-border shadow-sm">
      <TableRow>
        <TableHead class="w-10">
          <Checkbox
            :checked="allSelected"
            aria-label="Select all rules"
            @update:checked="(value) => emit('selectAll', value === true)"
          />
        </TableHead>
        <TableHead class="w-44 lg:w-56 text-xs uppercase font-semibold">Rule ID</TableHead>
        <TableHead class="hidden md:table-cell w-28 lg:w-32 text-xs uppercase font-semibold">Source</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Rule</TableHead>
        <TableHead class="w-24 text-xs uppercase font-semibold">Severity</TableHead>
        <TableHead class="hidden sm:table-cell w-28 lg:w-32 text-xs uppercase font-semibold">Action</TableHead>
        <TableHead class="hidden xl:table-cell w-16 text-xs uppercase font-semibold">Phase</TableHead>
        <TableHead class="w-20 lg:w-24 text-right text-xs uppercase font-semibold">Enabled</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="rule in rules" :key="rule.id" :data-testid="`catalog-row-${rule.id}`">
        <TableCell>
          <Checkbox
            :checked="selected.has(rule.id)"
            :aria-label="`Select ${rule.id}`"
            @update:checked="(value) => emit('select', rule.id, value === true)"
          />
        </TableCell>
        <TableCell>
          <div class="flex items-center gap-1 min-w-0">
            <Button
              variant="link"
              size="sm"
              class="h-auto p-0 font-mono text-xs font-semibold justify-start truncate text-primary hover:underline"
              :data-testid="`catalog-open-${rule.id}`"
              @click="emit('open', rule)"
            >
              {{ rule.id }}
            </Button>
            <span v-if="rule.overridden" class="text-warning text-xs" aria-label="Overridden">●</span>
          </div>
        </TableCell>
        <TableCell class="hidden md:table-cell whitespace-nowrap">
          <Badge
            variant="outline"
            class="font-mono text-xs text-muted-foreground whitespace-nowrap"
            :title="rule.pack_name || rule.source"
          >
            {{ sourceBadgeText(rule) }}
          </Badge>
        </TableCell>
        <TableCell class="min-w-0">
          <span
            class="text-xs font-medium text-foreground truncate block max-w-sm sm:max-w-md lg:max-w-lg"
            :title="rule.name"
          >
            {{ formatRuleName(rule.name) }}
          </span>
          <div class="flex items-center gap-1.5 text-xs text-muted-foreground mt-0.5 truncate max-w-sm sm:max-w-md">
            <span class="md:hidden font-mono px-1 py-0.2 rounded bg-muted text-muted-foreground border border-border">
              {{ sourceBadgeText(rule) }}
            </span>
            <span class="truncate">{{ rule.category }}</span>
          </div>
        </TableCell>
        <TableCell>
          <Badge variant="outline" class="font-mono text-xs" :class="severityClass(rule.severity)">
            {{ rule.severity?.toUpperCase() || 'INFO' }}
          </Badge>
        </TableCell>
        <TableCell class="hidden sm:table-cell">
          <Select
            v-if="canEdit"
            :model-value="rule.action || 'inherit'"
            @update:model-value="(value) => emit('action', rule, String(value))"
          >
            <SelectTrigger
              class="h-7 w-26 lg:w-28 text-xs bg-card border-border text-foreground"
              :disabled="pending.has(rule.id)"
              :data-testid="`catalog-action-${rule.id}`"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent class="border-border bg-popover text-popover-foreground">
              <SelectItem v-for="option in actionOptions" :key="option.value" :value="option.value" class="text-xs">
                {{ option.label }}
              </SelectItem>
            </SelectContent>
          </Select>
          <Badge v-else variant="outline" class="font-mono text-xs">{{ rule.action }}</Badge>
        </TableCell>
        <TableCell class="hidden xl:table-cell">
          <span class="font-mono text-xs text-muted-foreground">{{ rule.phase ?? '—' }}</span>
        </TableCell>
        <TableCell class="text-right">
          <div class="inline-flex items-center gap-2 justify-end">
            <Loader2 v-if="pending.has(rule.id)" class="w-3.5 h-3.5 animate-spin text-muted-foreground" />
            <Switch
              v-if="canEdit"
              :checked="rule.enabled"
              :data-testid="`catalog-toggle-${rule.id}`"
              @update:checked="(value) => emit('toggle', rule, value)"
            />
            <Badge v-else variant="outline" class="font-mono text-xs">
              {{ rule.enabled ? 'ON' : 'OFF' }}
            </Badge>
          </div>
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
