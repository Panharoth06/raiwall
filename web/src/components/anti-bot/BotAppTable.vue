<script setup lang="ts">
import type { BotAppRow, BotAppStatus } from './types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Bot, RefreshCw, Settings2, ShieldAlert } from 'lucide-vue-next';

defineProps<{
  rows: BotAppRow[];
  loading?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: 'configure', row: BotAppRow): void;
  (e: 'retry'): void;
}>();

const statusCopy: Record<BotAppStatus, string> = {
  on: 'On',
  off: 'Off',
  inherit: 'Inherits global',
  partial: 'Partial',
  paused: 'Paused',
  unconfigured: 'Not configured',
};

const statusVariant = (status: BotAppStatus) => {
  if (status === 'on') return 'success' as const;
  if (status === 'partial') return 'warning' as const;
  if (status === 'paused') return 'threat' as const;
  return 'outline' as const;
};

const visibleHosts = (row: BotAppRow) => row.hostnames.slice(0, 2);
const hiddenHosts = (row: BotAppRow) => Math.max(row.hostnames.length - 2, 0);
</script>

<template>
  <div class="bg-card border border-border rounded-lg min-w-0" data-testid="bot-app-table">
    <div class="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-border">
      <div class="flex items-center gap-2 min-w-0">
        <Bot class="w-4 h-4 text-muted-foreground shrink-0" />
        <h2 class="text-xs font-semibold uppercase tracking-wider text-foreground truncate">
          Applications
        </h2>
        <Badge variant="outline" class="font-mono text-[10px]">{{ rows.length }}</Badge>
      </div>
      <span class="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
        Application-scoped policy
      </span>
    </div>

    <div v-if="loading" class="p-4 space-y-2" data-testid="bot-app-loading">
      <div v-for="i in 4" :key="i" class="h-10 rounded bg-muted/60 animate-pulse" />
    </div>

    <div v-else-if="error" class="p-8 text-center" data-testid="bot-app-error">
      <ShieldAlert class="w-8 h-8 text-threat mx-auto mb-2" />
      <h3 class="text-xs font-semibold uppercase tracking-wider text-foreground">
        Could not load bot policies
      </h3>
      <p class="mt-1 mb-4 text-[11px] text-muted-foreground font-mono break-all">{{ error }}</p>
      <Button variant="outline" size="sm" class="gap-1.5" @click="emit('retry')">
        <RefreshCw class="w-3.5 h-3.5" />
        <span>Retry</span>
      </Button>
    </div>

    <!-- Desktop table -->
    <div v-else class="hidden lg:block overflow-x-auto">
      <Table class="min-w-[680px]">
        <TableHeader>
          <TableRow>
            <TableHead>Application</TableHead>
            <TableHead>Hostnames</TableHead>
            <TableHead>BOT Protect</TableHead>
            <TableHead>PoW difficulty</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
            v-for="row in rows"
            :key="row.id"
            :data-testid="row.global ? 'bot-global-row' : 'bot-app-row'"
            class="transition-colors duration-150"
          >
            <TableCell class="min-w-[150px]">
              <div class="flex items-center gap-2 min-w-0">
                <span class="font-medium text-foreground truncate" :title="row.name">
                  {{ row.name }}
                </span>
                <Badge v-if="row.global" variant="outline" class="font-mono text-[9px] uppercase">
                  fallback
                </Badge>
              </div>
            </TableCell>

            <TableCell class="max-w-[240px]">
              <div v-if="row.global" class="font-mono text-xs text-muted-foreground">*</div>
              <div v-else-if="row.hostnames.length" class="flex flex-wrap gap-1">
                <span
                  v-for="host in visibleHosts(row)"
                  :key="host"
                  class="max-w-[170px] truncate rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                  :title="host"
                >
                  {{ host }}
                </span>
                <span
                  v-if="hiddenHosts(row) > 0"
                  class="px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                  :title="row.hostnames.join('\n')"
                >
                  +{{ hiddenHosts(row) }}
                </span>
              </div>
              <span v-else class="font-mono text-[11px] text-muted-foreground">no hostnames</span>
            </TableCell>

            <TableCell>
              <div class="flex flex-wrap items-center gap-1.5">
                <Badge
                  :variant="statusVariant(row.status)"
                  class="font-mono uppercase text-[10px]"
                  data-testid="bot-row-status"
                >
                  {{ statusCopy[row.status] }}
                </Badge>
                <span
                  v-if="row.coverage && row.status === 'partial'"
                  class="font-mono text-[10px] text-muted-foreground"
                >
                  {{ row.coverage.custom }}/{{ row.coverage.total }} hosts
                </span>
              </div>
            </TableCell>

            <TableCell class="font-mono text-[11px] tabular-nums text-muted-foreground">
              {{ row.difficulty ? row.difficulty.toLocaleString('en-US') : '—' }}
            </TableCell>

            <TableCell class="text-right">
              <Button
                variant="outline"
                size="sm"
                class="h-7 gap-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider"
                :data-testid="row.global ? 'bot-configure-global' : 'bot-configure-app'"
                @click="emit('configure', row)"
              >
                <Settings2 class="w-3 h-3" />
                <span>BOT Protect</span>
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Tablet / mobile list -->
    <div v-if="!loading && !error" class="lg:hidden divide-y divide-border/60">
      <div
        v-for="row in rows"
        :key="`mobile-${row.id}`"
        class="p-3 space-y-2"
        :data-testid="row.global ? 'bot-global-card' : 'bot-app-card'"
      >
        <div class="flex items-start justify-between gap-2">
          <div class="flex flex-wrap items-center gap-1.5 min-w-0">
            <span class="text-xs font-medium text-foreground truncate">{{ row.name }}</span>
            <Badge v-if="row.global" variant="outline" class="font-mono text-[9px] uppercase">
              fallback
            </Badge>
          </div>
          <Badge
            :variant="statusVariant(row.status)"
            class="shrink-0 font-mono uppercase text-[10px]"
          >
            {{ statusCopy[row.status] }}
          </Badge>
        </div>

        <p class="font-mono text-[10px] text-muted-foreground break-all">
          {{ row.global ? 'All unconfigured hosts' : row.hostnames.join(' · ') || 'no hostnames' }}
        </p>

        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-[10px] text-muted-foreground tabular-nums">
            {{ row.difficulty ? `${row.difficulty.toLocaleString('en-US')} iters` : 'no challenge' }}
            <span class="mx-1 text-border">·</span>
            {{ row.traps }} traps
            <template v-if="row.coverage && row.status === 'partial'">
              <span class="mx-1 text-border">·</span>
              {{ row.coverage.custom }}/{{ row.coverage.total }} hosts
            </template>
          </span>
          <Button
            variant="outline"
            size="sm"
            class="h-7 shrink-0 gap-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider"
            :data-testid="row.global ? 'bot-configure-global-mobile' : 'bot-configure-app-mobile'"
            @click="emit('configure', row)"
          >
            <Settings2 class="w-3 h-3" />
            <span>BOT Protect</span>
          </Button>
        </div>
      </div>
    </div>

    <div class="px-4 py-2 border-t border-border/60">
      <p class="text-[10px] text-muted-foreground font-mono">
        Exact Host header matching. Applications without an override inherit the global fallback.
        Changes compile on the next deployment.
      </p>
    </div>
  </div>
</template>
