<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import type { BanEntry } from '@/api/client';
import { Button } from '@/components/ui/button';
import {
  X,
  ShieldAlert,
  Globe,
  Copy,
  Check,
  Clock,
  Fingerprint,
  Terminal,
  ShieldCheck,
  AlertTriangle,
  Loader2,
} from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  entry: BanEntry | null;
  unblocking?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:open', val: boolean): void;
  (e: 'unblock', entry: BanEntry): void;
}>();

const copiedField = ref<string | null>(null);

const handleCopy = async (text: string, field: string) => {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    copiedField.value = field;
    setTimeout(() => {
      if (copiedField.value === field) copiedField.value = null;
    }, 2000);
  } catch {
    // fallback
  }
};

const handleKeydown = (e: KeyboardEvent) => {
  if (e.key === 'Escape' && props.open) {
    emit('update:open', false);
  }
};

onMounted(() => {
  window.addEventListener('keydown', handleKeydown);
});

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeydown);
});

const close = () => {
  emit('update:open', false);
};

// Formatter and parser for reason details
const parsedReason = computed(() => {
  const r = props.entry?.reason || '';
  let ruleId = '';
  let detailReason = '';
  let paramInfo = '';
  let tierLabel = 'Access Velocity (Tier 1)';
  let tierVariant = 'info';

  if (r.toLowerCase().includes('tier2') || r.toLowerCase().includes('attack')) {
    tierLabel = 'Attack Frequency Threshold (Tier 2)';
    tierVariant = 'threat';
  } else if (r.toLowerCase().includes('tier3') || r.toLowerCase().includes('scanner') || r.toLowerCase().includes('error')) {
    tierLabel = 'Scanner Trap & Error Limit (Tier 3)';
    tierVariant = 'warning';
  }

  const ruleMatch = r.match(/rule=([^\s]+)/);
  if (ruleMatch) ruleId = ruleMatch[1];

  const reasonMatch = r.match(/reason=([^()]+(?:\([^)]+\))?)/);
  if (reasonMatch) detailReason = reasonMatch[1].trim();

  const paramMatch = r.match(/\(param\s+"([^"]+)"\s+in\s+([^)]+)\)/);
  if (paramMatch) paramInfo = `${paramMatch[1]} (${paramMatch[2]})`;

  return {
    raw: r,
    ruleId: ruleId || (tierVariant === 'threat' ? 'ATTACK_THRESHOLD' : 'VELOCITY_CAP'),
    detailReason: detailReason || r,
    paramInfo,
    tierLabel,
    tierVariant,
  };
});

const formatDuration = (seconds?: number) => {
  if (!seconds) return '30 minutes';
  const mins = Math.max(1, Math.round(seconds / 60));
  if (mins >= 60) {
    const h = (mins / 60).toFixed(1);
    return `${mins} minutes (${h} hours)`;
  }
  return `${mins} minutes`;
};

const formatCountdown = (seconds: number): string => {
  if (seconds <= 0) return 'Expired';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) {
    return `${h}h ${m < 10 ? '0' : ''}${m}m ${s < 10 ? '0' : ''}${s}s remaining`;
  }
  return `${m}m ${s < 10 ? '0' : ''}${s}s remaining`;
};
</script>

<template>
  <Teleport to="body">
    <!-- Backdrop -->
    <Transition
      enter-active-class="transition duration-150 ease-out"
      enter-from-class="opacity-0"
      enter-to-class="opacity-100"
      leave-active-class="transition duration-100 ease-in"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs"
        @click="close"
      />
    </Transition>

    <!-- Slide-over Drawer Panel -->
    <Transition
      enter-active-class="transform transition duration-200 ease-out"
      enter-from-class="translate-x-full"
      enter-to-class="translate-x-0"
      leave-active-class="transform transition duration-150 ease-in"
      leave-from-class="translate-x-0"
      leave-to-class="translate-x-full"
    >
      <div
        v-if="open && entry"
        class="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-card border-l border-border shadow-2xl flex flex-col font-sans text-card-foreground select-text"
      >
        <!-- Header -->
        <div class="px-6 py-4 border-b border-border bg-muted/20 flex items-center justify-between shrink-0">
          <div class="flex items-center gap-3 min-w-0">
            <div class="p-2 rounded-lg bg-threat/10 border border-threat/20 text-threat shrink-0">
              <ShieldAlert class="h-4 w-4" />
            </div>
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <h3 class="text-base font-semibold font-mono text-foreground truncate">
                  {{ entry.client_ip || entry.key }}
                </h3>
                <span class="px-1.5 py-0.5 rounded text-xs font-semibold uppercase bg-threat/15 text-threat border border-threat/25">
                  Banned
                </span>
              </div>
              <div class="text-xs text-muted-foreground flex items-center gap-1.5 mt-0.5">
                <Clock class="h-3 w-3 shrink-0" />
                <span class="font-mono tabular-nums">{{ formatCountdown(entry.remaining_seconds) }}</span>
              </div>
            </div>
          </div>

          <Button
            variant="ghost"
            size="sm"
            class="h-8 w-8 p-0 text-muted-foreground hover:text-foreground"
            @click="close"
          >
            <X class="h-4 w-4" />
          </Button>
        </div>

        <!-- Scrollable Content -->
        <div class="flex-1 min-h-0 overflow-y-auto p-6 space-y-5 text-xs">
          <!-- Trigger Overview -->
          <div class="p-3.5 rounded-lg border border-border bg-muted/10 space-y-2.5">
            <div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Defense Trigger
            </div>
            <div class="flex items-center justify-between">
              <span class="text-muted-foreground">Policy Tier</span>
              <span class="font-medium text-foreground">{{ parsedReason.tierLabel }}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-muted-foreground">Rule ID</span>
              <span class="font-mono font-semibold px-1.5 py-0.5 rounded bg-muted text-foreground border border-border">
                {{ parsedReason.ruleId }}
              </span>
            </div>
            <div v-if="parsedReason.paramInfo" class="flex items-center justify-between">
              <span class="text-muted-foreground">Target Parameter</span>
              <span class="font-mono text-foreground bg-muted/80 px-1.5 py-0.5 rounded border border-border">
                {{ parsedReason.paramInfo }}
              </span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-muted-foreground">Banned At</span>
              <span class="font-mono tabular-nums text-foreground">{{ entry.banned_at || 'Just now' }}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-muted-foreground">Duration</span>
              <span class="font-mono tabular-nums text-foreground">{{ formatDuration(entry.duration) }}</span>
            </div>
          </div>

          <!-- Diagnostic Log Box -->
          <div class="space-y-1.5">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <Terminal class="h-3 w-3" />
                Raw Violation Diagnostics
              </span>
              <Button
                variant="ghost"
                size="sm"
                class="h-6 px-2 text-xs text-muted-foreground hover:text-foreground"
                @click="handleCopy(parsedReason.raw, 'raw')"
              >
                <Check v-if="copiedField === 'raw'" class="h-3 w-3 mr-1 text-success" />
                <Copy v-else class="h-3 w-3 mr-1" />
                {{ copiedField === 'raw' ? 'Copied' : 'Copy Log' }}
              </Button>
            </div>
            <div class="p-3 rounded-lg border border-border bg-muted/40 font-mono text-xs text-foreground leading-relaxed break-all select-all whitespace-pre-wrap">
              {{ parsedReason.raw }}
            </div>
          </div>

          <!-- Identifiers & Fingerprint -->
          <div class="space-y-3">
            <div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Fingerprint class="h-3 w-3" />
              Fingerprint & Keys
            </div>

            <div v-if="entry.ja4" class="p-2.5 rounded-lg border border-border bg-card space-y-1">
              <div class="flex items-center justify-between">
                <span class="text-xs text-muted-foreground font-mono">JA4 TLS Hash</span>
                <Button
                  variant="ghost"
                  size="sm"
                  class="h-5 px-1.5 text-xs text-muted-foreground hover:text-foreground"
                  @click="handleCopy(entry.ja4, 'ja4')"
                >
                  <Check v-if="copiedField === 'ja4'" class="h-2.5 w-2.5 mr-0.5 text-success" />
                  <Copy v-else class="h-2.5 w-2.5 mr-0.5" />
                  {{ copiedField === 'ja4' ? 'Copied' : 'Copy' }}
                </Button>
              </div>
              <div class="font-mono text-xs text-foreground truncate select-all">{{ entry.ja4 }}</div>
            </div>

            <div class="p-2.5 rounded-lg border border-border bg-card space-y-1">
              <div class="flex items-center justify-between">
                <span class="text-xs text-muted-foreground font-mono">Composite Ban Key</span>
                <Button
                  variant="ghost"
                  size="sm"
                  class="h-5 px-1.5 text-xs text-muted-foreground hover:text-foreground"
                  @click="handleCopy(entry.key, 'key')"
                >
                  <Check v-if="copiedField === 'key'" class="h-2.5 w-2.5 mr-0.5 text-success" />
                  <Copy v-else class="h-2.5 w-2.5 mr-0.5" />
                  {{ copiedField === 'key' ? 'Copied' : 'Copy' }}
                </Button>
              </div>
              <div class="font-mono text-xs text-foreground truncate select-all">{{ entry.key }}</div>
            </div>
          </div>
        </div>

        <!-- Footer Actions -->
        <div class="px-6 py-3.5 border-t border-border bg-muted/10 flex items-center justify-between shrink-0">
          <Button
            variant="outline"
            size="sm"
            class="h-8 text-xs font-medium"
            @click="close"
          >
            Close
          </Button>

          <Button
            variant="destructive"
            size="sm"
            class="h-8 text-xs font-medium gap-1.5"
            :disabled="unblocking"
            @click="emit('unblock', entry)"
          >
            <Loader2 v-if="unblocking" class="h-3.5 w-3.5 animate-spin" />
            <ShieldCheck v-else class="h-3.5 w-3.5" />
            Unblock Client IP
          </Button>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
