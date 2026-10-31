<script setup lang="ts">
import { ref } from 'vue';
import type { ForensicEvent } from '@/types/telemetry';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Activity, Check, Copy } from 'lucide-vue-next';

defineProps<{
  open: boolean;
  event: ForensicEvent | null;
}>();

const emit = defineEmits<{
  (e: 'update:open', val: boolean): void;
}>();

const copiedJa4 = ref(false);

const formatTime = (value?: string) => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toISOString().replace('T', ' ').slice(0, 19);
};

const copyJa4 = (val?: string) => {
  if (!val) return;
  navigator.clipboard.writeText(val);
  copiedJa4.value = true;
  setTimeout(() => {
    copiedJa4.value = false;
  }, 2000);
};

const statusVariant = (statusCode?: number, action?: string) => {
  if (action === 'ban' || statusCode === 403) return 'destructive';
  if (statusCode === 468 || action === 'challenge') return 'warning';
  if (statusCode === 200 || action === 'allow') return 'secondary';
  return 'outline';
};
</script>

<template>
  <Dialog :open="open" @update:open="(val) => emit('update:open', val)">
    <DialogContent class="max-w-xl max-h-[85vh] overflow-y-auto font-sans" data-testid="bot-event-detail-dialog">
      <DialogHeader>
        <div class="flex items-center gap-2">
          <Activity class="w-5 h-5 text-primary" />
          <DialogTitle class="text-base font-semibold">Bot Forensic Event Details</DialogTitle>
        </div>
        <DialogDescription class="text-xs text-muted-foreground">
          Complete telemetry metadata and fingerprint analysis for event <code class="font-mono">{{ event?.event_id }}</code>.
        </DialogDescription>
      </DialogHeader>

      <div v-if="event" class="space-y-4 py-2 text-xs">
        <!-- Key summary cards -->
        <div class="grid grid-cols-2 gap-3">
          <div class="p-3 bg-muted/40 rounded-lg border border-border">
            <span class="text-muted-foreground uppercase font-mono block mb-1">Status Code</span>
            <div class="flex items-center gap-2">
              <Badge :variant="statusVariant(event.status_code, event.action)" class="text-xs font-mono">
                {{ event.status_code }} {{ event.action?.toUpperCase() }}
              </Badge>
            </div>
          </div>
          <div class="p-3 bg-muted/40 rounded-lg border border-border">
            <span class="text-muted-foreground uppercase font-mono block mb-1">Timestamp</span>
            <span class="font-mono font-medium text-foreground">{{ formatTime(event.timestamp) }}</span>
          </div>
        </div>

        <!-- Connection & Target info -->
        <div class="space-y-2 p-3 bg-card rounded-lg border border-border">
          <div class="flex justify-between py-1 border-b border-border/60">
            <span class="text-muted-foreground">Client IP:</span>
            <span class="font-mono font-medium text-foreground">{{ event.client_ip }}</span>
          </div>
          <div class="flex justify-between py-1 border-b border-border/60">
            <span class="text-muted-foreground">Host:</span>
            <span class="font-mono font-medium text-foreground">{{ event.host }}</span>
          </div>
          <div class="flex justify-between py-1 border-b border-border/60">
            <span class="text-muted-foreground">Method & Path:</span>
            <span class="font-mono font-medium text-foreground truncate max-w-sm">{{ event.method }} {{ event.path }}</span>
          </div>
          <div class="flex justify-between items-center py-1 border-b border-border/60">
            <span class="text-muted-foreground">JA4 Fingerprint:</span>
            <div class="flex items-center gap-1.5 font-mono text-foreground">
              <span>{{ event.ja4 || 'None' }}</span>
              <Button
                v-if="event.ja4"
                variant="ghost"
                size="sm"
                class="h-6 w-6 p-0"
                @click="copyJa4(event.ja4)"
              >
                <Check v-if="copiedJa4" class="w-3 h-3 text-success" />
                <Copy v-else class="w-3 h-3 text-muted-foreground" />
              </Button>
            </div>
          </div>
          <div v-if="event.rule_id" class="flex justify-between py-1">
            <span class="text-muted-foreground">Rule Triggered:</span>
            <span class="font-mono text-primary font-medium">{{ event.rule_id }}</span>
          </div>
        </div>

        <!-- Raw Headers & Metadata JSON -->
        <div v-if="event.headers && Object.keys(event.headers).length > 0" class="space-y-1.5">
          <span class="text-xs font-mono font-semibold uppercase tracking-wider text-muted-foreground">
            Request Headers
          </span>
          <pre class="p-3 rounded-lg border border-border bg-muted/40 font-mono text-xs overflow-x-auto text-foreground">{{ JSON.stringify(event.headers, null, 2) }}</pre>
        </div>
      </div>
    </DialogContent>
  </Dialog>
</template>
