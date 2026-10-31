<script setup lang="ts">
import type { DetectionRulePack } from '@/api/detection';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Trash2 } from 'lucide-vue-next';

defineProps<{
  packs: DetectionRulePack[];
  canEdit: boolean;
  pending: Set<string>;
}>();

const emit = defineEmits<{
  toggle: [pack: DetectionRulePack, enabled: boolean];
  remove: [pack: DetectionRulePack];
}>();

const statusClass = (pack: DetectionRulePack) => {
  if (pack.builtin) return 'border-border bg-muted text-muted-foreground';
  return pack.enabled
    ? 'border-success/30 bg-success/10 text-success'
    : 'border-border bg-muted text-muted-foreground';
};
</script>

<template>
  <Table data-testid="rule-pack-table" container-class="overflow-visible">
    <TableHeader>
      <TableRow>
        <TableHead class="text-xs uppercase font-semibold">Pack</TableHead>
        <TableHead class="w-24 text-xs uppercase font-semibold">Type</TableHead>
        <TableHead class="w-28 text-xs uppercase font-semibold">Relation</TableHead>
        <TableHead class="w-20 text-right text-xs uppercase font-semibold">Rules</TableHead>
        <TableHead class="w-28 text-xs uppercase font-semibold">Status</TableHead>
        <TableHead class="w-20 text-right text-xs uppercase font-semibold">Priority</TableHead>
        <TableHead class="w-32 text-right text-xs uppercase font-semibold">Enabled</TableHead>
        <TableHead class="w-20 text-right text-xs uppercase font-semibold">Remove</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="pack in packs" :key="pack.id" :data-testid="`pack-row-${pack.id}`">
        <TableCell class="min-w-0">
          <div class="text-sm font-medium text-foreground truncate">{{ pack.name }}</div>
          <div class="text-xs font-mono text-muted-foreground truncate">{{ pack.id }} · v{{ pack.version }}</div>
        </TableCell>
        <TableCell>
          <Badge variant="outline" class="font-mono text-xs">{{ pack.type }}</Badge>
        </TableCell>
        <TableCell>
          <span class="font-mono text-xs text-muted-foreground">{{ pack.relation }}</span>
        </TableCell>
        <TableCell class="text-right">
          <span class="font-mono tabular-nums text-xs text-foreground">{{ pack.rules_count }}</span>
        </TableCell>
        <TableCell>
          <Badge variant="outline" class="font-mono text-xs" :class="statusClass(pack)">
            {{ pack.status.toUpperCase() }}
          </Badge>
        </TableCell>
        <TableCell class="text-right">
          <span class="font-mono tabular-nums text-xs text-muted-foreground">{{ pack.priority }}</span>
        </TableCell>
        <TableCell class="text-right">
          <div class="inline-flex items-center gap-2">
            <Switch
              v-if="canEdit && !pack.builtin"
              :checked="pack.enabled"
              :disabled="pending.has(pack.id)"
              :data-testid="`pack-toggle-${pack.id}`"
              @update:checked="(value) => emit('toggle', pack, value)"
            />
            <Badge v-else variant="outline" class="font-mono text-xs">
              {{ pack.enabled ? 'ON' : 'OFF' }}
            </Badge>
          </div>
        </TableCell>
        <TableCell class="text-right">
          <Button
            v-if="canEdit && !pack.builtin"
            variant="ghost"
            size="icon"
            class="h-7 w-7 text-muted-foreground hover:text-threat"
            :disabled="pending.has(pack.id)"
            :data-testid="`pack-delete-${pack.id}`"
            :aria-label="`Remove ${pack.name}`"
            @click="emit('remove', pack)"
          >
            <Trash2 class="w-3.5 h-3.5" />
          </Button>
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
