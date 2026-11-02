<script setup lang="ts">
import type { AuditChainReport } from '@/api/client';
import { Button } from '@/components/ui/button';
import { ShieldAlert, ShieldCheck } from 'lucide-vue-next';

defineProps<{
  report: AuditChainReport | null;
  error: string;
  loading: boolean;
}>();

const emit = defineEmits<{ (event: 'retry'): void }>();
</script>

<template>
  <div
    v-if="loading"
    class="rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-xs text-muted-foreground"
    aria-busy="true"
  >
    Re-hashing the audit chain…
  </div>

  <div
    v-else-if="error"
    class="flex items-center gap-2 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-sm text-threat"
  >
    <ShieldAlert class="h-4 w-4 shrink-0" />
    <span class="min-w-0 flex-1 truncate">{{ error }}</span>
    <Button variant="outline" size="sm" @click="emit('retry')">Retry</Button>
  </div>

  <div
    v-else-if="report"
    class="rounded-md border px-3 py-2 text-sm"
    :class="report.valid ? 'border-success/30 bg-success/10 text-success' : 'border-threat/30 bg-threat/10 text-threat'"
    role="status"
  >
    <div class="flex items-center gap-2">
      <ShieldCheck v-if="report.valid" class="h-4 w-4 shrink-0" />
      <ShieldAlert v-else class="h-4 w-4 shrink-0" />
      <span class="font-medium">
        {{ report.valid ? 'Chain intact' : `Chain broken at sequence ${report.broken_at_seq ?? '—'}` }}
      </span>
      <span class="min-w-0 flex-1 truncate text-xs text-muted-foreground">
        {{ report.checked }} events · {{ report.anchors.checked }} anchors
        <template v-if="report.anchors.key_fingerprint"> · {{ report.anchors.key_fingerprint }}</template>
        <template v-if="report.unchained"> · {{ report.unchained }} legacy unchained</template>
      </span>
      <Button variant="outline" size="sm" @click="emit('retry')">Re-verify</Button>
    </div>
    <p v-if="!report.valid && report.reason" class="mt-1 text-xs">{{ report.reason }}</p>
  </div>
</template>
