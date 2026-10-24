<script setup lang="ts">
import type { BotConfig } from '@/api/bot';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Bot, Plus, Pencil, Trash2, ShieldAlert, RefreshCw } from 'lucide-vue-next';

defineProps<{
  configs: BotConfig[];
  loading?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: 'add'): void;
  (e: 'edit', config: BotConfig): void;
  (e: 'remove', config: BotConfig): void;
  (e: 'toggle', config: BotConfig): void;
  (e: 'retry'): void;
}>();

const trapSummary = (config: BotConfig) => config.trap_urls?.[0] ?? '';
const extraTraps = (config: BotConfig) => Math.max((config.trap_urls?.length ?? 0) - 1, 0);
</script>

<template>
  <div class="bg-card border border-border rounded-lg min-w-0" data-testid="bot-host-card">
    <div class="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-border">
      <div class="flex items-center gap-2 min-w-0">
        <Bot class="w-4 h-4 text-muted-foreground shrink-0" />
        <h2 class="text-xs font-semibold uppercase tracking-wider text-foreground truncate">
          Per-Host Overrides
        </h2>
        <Badge variant="outline" class="font-mono text-[10px]">{{ configs.length }}</Badge>
      </div>

      <Button
        size="sm"
        class="h-8 gap-1.5 text-[11px] font-semibold uppercase tracking-wider"
        data-testid="bot-add-host"
        @click="emit('add')"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>Add Override</span>
      </Button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="p-4 space-y-2" data-testid="bot-host-loading">
      <div v-for="i in 3" :key="i" class="h-9 rounded bg-muted/60 animate-pulse" />
    </div>

    <!-- Error -->
    <div v-else-if="error" class="p-8 text-center" data-testid="bot-host-error">
      <ShieldAlert class="w-8 h-8 text-threat mx-auto mb-2" />
      <h3 class="text-xs font-semibold uppercase tracking-wider text-foreground">
        Could not load per-host overrides
      </h3>
      <p class="mt-1 mb-4 text-[11px] text-muted-foreground font-mono break-all">{{ error }}</p>
      <Button variant="outline" size="sm" class="gap-1.5" @click="emit('retry')">
        <RefreshCw class="w-3.5 h-3.5" />
        <span>Retry</span>
      </Button>
    </div>

    <!-- Empty -->
    <div v-else-if="configs.length === 0" class="p-10 text-center" data-testid="bot-host-empty">
      <Bot class="w-9 h-9 text-muted-foreground mx-auto mb-3" />
      <h3 class="text-xs font-semibold uppercase tracking-wider text-foreground">
        No per-host overrides
      </h3>
      <p class="mx-auto mt-1 mb-4 max-w-sm text-[11px] leading-relaxed text-muted-foreground">
        Every site uses the global policy above. Add an override to tune PoW difficulty or trap URLs
        for one host.
      </p>
      <Button variant="outline" size="sm" class="gap-1.5" @click="emit('add')">
        <Plus class="w-3.5 h-3.5" />
        <span>Add First Override</span>
      </Button>
    </div>

    <!-- Table -->
    <div v-else class="overflow-x-auto">
      <Table class="min-w-[720px]">
        <TableHeader>
          <TableRow>
            <TableHead class="font-mono text-[11px]">Host</TableHead>
            <TableHead class="font-mono text-[11px]">PoW</TableHead>
            <TableHead class="font-mono text-[11px]">Difficulty</TableHead>
            <TableHead class="font-mono text-[11px]">Trap URL</TableHead>
            <TableHead class="font-mono text-[11px]">Active</TableHead>
            <TableHead class="font-mono text-[11px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
            v-for="config in configs"
            :key="config.id"
            data-testid="bot-host-row"
            class="transition-colors duration-150"
          >
            <TableCell class="font-mono text-xs text-foreground max-w-[220px] truncate" :title="config.host">
              {{ config.host }}
            </TableCell>
            <TableCell>
              <Badge
                :variant="config.pow_enabled ? 'success' : 'outline'"
                class="font-mono uppercase text-[10px]"
              >
                {{ config.pow_enabled ? 'On' : 'Off' }}
              </Badge>
            </TableCell>
            <TableCell class="font-mono text-[11px] tabular-nums text-muted-foreground">
              {{ config.pow_enabled ? config.pow_difficulty.toLocaleString('en-US') : '—' }}
            </TableCell>
            <TableCell class="max-w-[240px]">
              <template v-if="trapSummary(config)">
                <span class="block truncate font-mono text-[11px] text-foreground" :title="config.trap_urls.join('\n')">
                  {{ trapSummary(config) }}
                </span>
                <span v-if="extraTraps(config) > 0" class="text-[10px] font-mono text-muted-foreground">
                  +{{ extraTraps(config) }} more
                </span>
              </template>
              <span v-else class="text-[11px] font-mono text-muted-foreground">—</span>
            </TableCell>
            <TableCell>
              <div class="flex items-center gap-2">
                <Switch
                  :checked="config.is_active"
                  :aria-label="`Toggle override for ${config.host}`"
                  data-testid="bot-toggle-host"
                  @update:checked="emit('toggle', config)"
                />
                <span class="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  {{ config.is_active ? 'On' : 'Paused' }}
                </span>
              </div>
            </TableCell>
            <TableCell class="text-right space-x-1">
              <Button
                variant="ghost"
                size="icon"
                class="h-7 w-7 text-muted-foreground hover:text-foreground"
                title="Edit override"
                data-testid="bot-edit-host"
                @click="emit('edit', config)"
              >
                <Pencil class="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                class="h-7 w-7 text-muted-foreground hover:text-threat"
                title="Delete override"
                data-testid="bot-delete-host"
                @click="emit('remove', config)"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <div v-if="!loading && !error && configs.length > 0" class="px-4 py-2 border-t border-border/60">
      <p class="text-[10px] text-muted-foreground font-mono">
        Overrides match the exact Host header. The wildcard policy is edited above; changes compile on the next deployment.
      </p>
    </div>
  </div>
</template>
