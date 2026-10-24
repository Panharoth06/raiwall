<script setup lang="ts">
import { computed } from 'vue';
import type { ACLRule } from '@/api/client';
import { formatConditionDetail } from './aclRuleTranspiler';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import {
  Plus,
  Edit2,
  Trash2,
  ChevronUp,
  ChevronDown,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-vue-next';

const props = defineProps<{
  rules: ACLRule[];
  loading?: boolean;
  activeTab: 'allow' | 'block';
}>();

const emit = defineEmits<{
  (e: 'edit', rule: ACLRule): void;
  (e: 'delete', ruleId: string): void;
  (e: 'toggle-status', rule: ACLRule): void;
  (e: 'move-up', rule: ACLRule, index: number): void;
  (e: 'move-down', rule: ACLRule, index: number): void;
  (e: 'add-rule'): void;
}>();

const formatDate = (dateStr?: string) => {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  } catch {
    return dateStr;
  }
};
</script>

<template>
  <div class="h-full flex flex-col bg-card border border-border rounded-lg overflow-hidden">
    <!-- Empty State -->
    <div v-if="rules.length === 0" class="flex-1 min-h-[360px] flex flex-col items-center justify-center p-12 text-center">
      <component
        :is="activeTab === 'allow' ? ShieldCheck : ShieldAlert"
        :class="['w-10 h-10 mx-auto mb-3', activeTab === 'allow' ? 'text-primary' : 'text-threat']"
      />
      <h3 class="text-xs font-semibold uppercase tracking-wider text-foreground">
        No {{ activeTab === 'allow' ? 'Whitelist' : 'Blacklist' }} Rules Configured
      </h3>
      <p class="text-sm text-muted-foreground mt-1 mb-4 max-w-md mx-auto leading-relaxed">
        {{
          activeTab === 'allow'
            ? 'Add rules to bypass inspection for trusted IP ranges, internal subnets, or partner API tokens.'
            : 'Add rules to block malicious scanner traffic, hostile CIDRs, or unauthorized methods.'
        }}
      </p>
      <Button
        @click="emit('add-rule')"
        class="gap-1.5"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>Add First Rule</span>
      </Button>
    </div>

    <!-- Rules Table -->
    <div v-else class="flex-1 overflow-y-auto">
      <Table container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="w-16">Order</TableHead>
            <TableHead class="w-28">Rule ID</TableHead>
            <TableHead class="w-20">Status</TableHead>
            <TableHead class="w-28">Type</TableHead>
            <TableHead class="w-48">Name</TableHead>
            <TableHead>Detail</TableHead>
            <TableHead class="w-24 text-right">Priority</TableHead>
            <TableHead class="w-36">Updated At</TableHead>
            <TableHead class="w-24 text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="(rule, idx) in rules" :key="rule.id">
            <!-- 1. Order with Up/Down buttons -->
            <TableCell>
              <div class="flex items-center gap-1">
                <span class="font-mono text-xs text-muted-foreground tabular-nums w-4">
                  {{ idx + 1 }}
                </span>
                <div class="flex flex-col">
                  <button
                    type="button"
                    :disabled="idx === 0"
                    @click="emit('move-up', rule, idx)"
                    class="text-muted-foreground hover:text-foreground disabled:opacity-20 cursor-pointer p-0.5"
                    title="Move up in priority"
                  >
                    <ChevronUp class="w-3 h-3" />
                  </button>
                  <button
                    type="button"
                    :disabled="idx === rules.length - 1"
                    @click="emit('move-down', rule, idx)"
                    class="text-muted-foreground hover:text-foreground disabled:opacity-20 cursor-pointer p-0.5"
                    title="Move down in priority"
                  >
                    <ChevronDown class="w-3 h-3" />
                  </button>
                </div>
              </div>
            </TableCell>

            <!-- 2. Rule ID -->
            <TableCell class="font-mono text-[11px] text-muted-foreground">
              {{ rule.id }}
            </TableCell>

            <!-- 3. Status Switch -->
            <TableCell>
              <Switch
                :checked="rule.enabled"
                @update:checked="emit('toggle-status', rule)"
              />
            </TableCell>

            <!-- 4. Type -->
            <TableCell>
              <Badge variant="outline" class="text-[10px] uppercase font-mono tracking-wider">
                Custom Rule
              </Badge>
            </TableCell>

            <!-- 5. Name -->
            <TableCell class="font-medium text-foreground text-xs">
              {{ rule.name }}
            </TableCell>

            <!-- 6. Detail (Condition Chips) -->
            <TableCell class="max-w-md">
              <div class="flex items-center gap-1.5 flex-wrap">
                <template v-for="(chip, cIdx) in formatConditionDetail(rule.expression)" :key="cIdx">
                  <Badge
                    v-if="chip.isConnector"
                    variant="outline"
                    class="font-mono text-[9px] uppercase px-1 py-0 border-primary/40 text-primary"
                  >
                    {{ chip.text }}
                  </Badge>
                  <span
                    v-else
                    class="font-mono text-[11px] bg-muted/60 text-foreground px-1.5 py-0.5 rounded border border-border/80 truncate max-w-xs"
                    :title="chip.text"
                  >
                    {{ chip.text }}
                  </span>
                </template>
              </div>
            </TableCell>

            <!-- 7. Priority -->
            <TableCell class="text-right font-mono text-[11px] tabular-nums text-muted-foreground">
              {{ rule.priority }}
            </TableCell>

            <!-- 8. Updated At -->
            <TableCell class="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
              {{ formatDate(rule.updated_at || rule.created_at) }}
            </TableCell>

            <!-- 9. Actions -->
            <TableCell class="text-right">
              <div class="flex items-center justify-end space-x-1">
                <Button
                  variant="ghost"
                  size="icon"
                  @click="emit('edit', rule)"
                  title="Edit rule"
                  class="h-7 w-7 text-muted-foreground hover:text-foreground"
                >
                  <Edit2 class="w-3.5 h-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  @click="emit('delete', rule.id)"
                  title="Delete rule"
                  class="h-7 w-7 text-muted-foreground hover:text-threat"
                >
                  <Trash2 class="w-3.5 h-3.5" />
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>
  </div>
</template>
