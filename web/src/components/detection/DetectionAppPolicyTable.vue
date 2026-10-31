<script setup lang="ts">
import { computed } from 'vue';
import type { AppDetectionPolicy, DetectionMode, Sensitivity, WAFPolicy } from '@/api/detection';
import { useAuthStore } from '@/stores/auth';
import { useRouter } from '@/router';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Loader2, RotateCcw, ShieldOff } from 'lucide-vue-next';

const props = defineProps<{
  policies: AppDetectionPolicy[];
  saving?: boolean;
}>();

const emit = defineEmits<{
  update: [appID: string, policy: WAFPolicy];
  reset: [appID: string];
}>();

const auth = useAuthStore();
const router = useRouter();
const canEdit = computed(() => auth.user?.role !== 'viewer');

const modeOptions: { value: DetectionMode; label: string }[] = [
  { value: 'inherit', label: 'Inherit' },
  { value: 'off', label: 'Off' },
  { value: 'alert', label: 'Alert' },
  { value: 'block', label: 'Block' },
];

const sensitivityOptions: { value: Sensitivity; label: string }[] = [
  { value: 'inherit', label: 'Inherit' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
];

const update = (row: AppDetectionPolicy, patch: Partial<WAFPolicy>) => {
  emit('update', row.app_id, { ...row.raw, ...patch });
};

const modeClass = (mode: string) => {
  switch (mode) {
    case 'block':
      return 'border-threat/30 bg-threat/10 text-threat';
    case 'alert':
      return 'border-warning/30 bg-warning/10 text-warning';
    case 'off':
      return 'border-border bg-muted text-muted-foreground';
    default:
      return 'border-border bg-muted text-muted-foreground';
  }
};
</script>

<template>
  <div class="rounded-lg border border-border bg-card overflow-x-auto">
    <Table v-if="policies.length" data-testid="app-detection-policy-table">
      <TableHeader>
        <TableRow>
          <TableHead class="text-xs uppercase font-semibold">Application</TableHead>
          <TableHead class="w-36 text-xs uppercase font-semibold">Effective Mode</TableHead>
          <TableHead class="w-36 text-xs uppercase font-semibold">Sensitivity</TableHead>
          <TableHead class="w-28 text-xs uppercase font-semibold">Source</TableHead>
          <TableHead class="w-24 text-right text-xs uppercase font-semibold">Reset</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow
          v-for="row in policies"
          :key="row.app_id"
          :data-testid="`app-policy-row-${row.app_id}`"
        >
          <TableCell class="min-w-0">
            <div class="text-sm font-medium text-foreground truncate">{{ row.name }}</div>
            <div class="text-xs font-mono text-muted-foreground truncate">{{ row.app_id }}</div>
          </TableCell>
          <TableCell>
            <Select
              v-if="canEdit"
              :model-value="row.raw.detection_mode || 'inherit'"
              @update:model-value="(value) => update(row, { detection_mode: value as DetectionMode })"
            >
              <SelectTrigger
                class="h-7 w-32 text-xs bg-background border-input"
                :disabled="saving"
                :data-testid="`app-mode-${row.app_id}`"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent class="border-border bg-popover text-popover-foreground">
                <SelectItem
                  v-for="option in modeOptions"
                  :key="option.value"
                  :value="option.value"
                  class="text-xs"
                >
                  {{ option.label }}
                </SelectItem>
              </SelectContent>
            </Select>
            <Badge v-else variant="outline" class="font-mono" :class="modeClass(row.policy.detection_mode)">
              {{ row.policy.detection_mode.toUpperCase() }}
            </Badge>
          </TableCell>
          <TableCell>
            <Select
              v-if="canEdit"
              :model-value="row.raw.sensitivity || 'inherit'"
              @update:model-value="(value) => update(row, { sensitivity: value as Sensitivity })"
            >
              <SelectTrigger
                class="h-7 w-32 text-xs bg-background border-input"
                :disabled="saving"
                :data-testid="`app-sensitivity-${row.app_id}`"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent class="border-border bg-popover text-popover-foreground">
                <SelectItem
                  v-for="option in sensitivityOptions"
                  :key="option.value"
                  :value="option.value"
                  class="text-xs"
                >
                  {{ option.label }}
                </SelectItem>
              </SelectContent>
            </Select>
            <span v-else class="text-xs font-mono text-muted-foreground">
              {{ row.policy.sensitivity }}
            </span>
          </TableCell>
          <TableCell>
            <Badge
              variant="outline"
              class="font-mono"
              :class="row.overridden ? 'border-warning/30 bg-warning/10 text-warning' : 'border-border bg-muted text-muted-foreground'"
            >
              {{ row.overridden ? 'OVERRIDE' : 'INHERITED' }}
            </Badge>
          </TableCell>
          <TableCell class="text-right">
            <Button
              v-if="canEdit && row.overridden"
              variant="ghost"
              size="sm"
              class="h-7 text-xs gap-1"
              :disabled="saving"
              :data-testid="`app-policy-reset-${row.app_id}`"
              @click="emit('reset', row.app_id)"
            >
              <Loader2 v-if="saving" class="w-3 h-3 animate-spin" />
              <RotateCcw v-else class="w-3 h-3" />
              <span>Reset</span>
            </Button>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>

    <EmptyState
      v-else
      :icon="ShieldOff"
      title="No protected applications"
      description="Add a site to give it a detection policy. Until then the global policy applies."
    >
      <Button size="sm" variant="outline" class="h-8 text-xs" @click="router.push('/sites')">
        Open Applications
      </Button>
    </EmptyState>
  </div>
</template>
