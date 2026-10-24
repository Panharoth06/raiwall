<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { BotConfig, BotConfigDraft } from '@/api/bot';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NumberInput } from '@/components/ui/number-input';
import { Switch } from '@/components/ui/switch';
import { Bot, Loader2, Save, ShieldAlert } from 'lucide-vue-next';

const MIN_DIFFICULTY = 1_000;
const MAX_DIFFICULTY = 200_000;
const DEFAULT_DIFFICULTY = 50_000;

const props = defineProps<{
  open: boolean;
  config?: BotConfig | null;
  suggestions?: string[];
  saving?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', draft: BotConfigDraft): void;
}>();

const host = ref('');
const powEnabled = ref(true);
const difficulty = ref<number | null>(DEFAULT_DIFFICULTY);
const trapsText = ref('');
const active = ref(true);
const localError = ref('');

const visibleSuggestions = computed(() =>
  (props.suggestions ?? []).filter((s) => s && s !== '*' && s !== host.value).slice(0, 6)
);

const difficultyInvalid = computed(() => {
  const value = difficulty.value ?? 0;
  return powEnabled.value && (value < MIN_DIFFICULTY || value > MAX_DIFFICULTY);
});

function reset() {
  host.value = props.config?.host ?? '';
  powEnabled.value = props.config?.pow_enabled ?? true;
  difficulty.value = props.config?.pow_difficulty || DEFAULT_DIFFICULTY;
  trapsText.value = (props.config?.trap_urls ?? []).join('\n');
  active.value = props.config?.is_active ?? true;
  localError.value = '';
}

watch(
  () => props.open,
  (open) => {
    if (open) reset();
  },
  { immediate: true }
);

function handleSave() {
  localError.value = '';
  const trimmedHost = host.value.trim();
  if (!trimmedHost) {
    localError.value = 'Host is required. Use the exact Host header value.';
    return;
  }

  const value = difficulty.value ?? DEFAULT_DIFFICULTY;
  if (powEnabled.value && (value < MIN_DIFFICULTY || value > MAX_DIFFICULTY)) {
    localError.value = `Difficulty must be between ${MIN_DIFFICULTY.toLocaleString()} and ${MAX_DIFFICULTY.toLocaleString()} iterations.`;
    return;
  }

  const traps = trapsText.value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const invalidTrap = traps.find((trap) => !trap.startsWith('/'));
  if (invalidTrap) {
    localError.value = `Trap URL "${invalidTrap}" must start with /.`;
    return;
  }

  emit('save', {
    host: trimmedHost,
    pow_enabled: powEnabled.value,
    pow_difficulty: value,
    trap_urls: traps,
    is_active: active.value,
  });
}
</script>

<template>
  <Dialog :open="open" @update:open="(value) => !value && emit('close')">
    <DialogContent class="max-w-lg max-h-[85vh] overflow-y-auto" data-testid="bot-host-dialog">
      <DialogHeader>
        <div class="flex items-center gap-2.5">
          <Bot class="w-5 h-5 text-muted-foreground" />
          <DialogTitle>{{ config ? 'Edit Host Override' : 'Add Host Override' }}</DialogTitle>
        </div>
        <DialogDescription class="text-[11px] text-muted-foreground">
          Tune proof-of-work and trap endpoints for one host. Other hosts inherit the global policy.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-1">
        <div>
          <label class="block mb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground">
            Host
          </label>
          <Input
            v-model="host"
            placeholder="app.example.com"
            class="font-mono"
            data-testid="bot-host-input"
          />
          <p class="mt-1 text-[10px] text-muted-foreground">
            Matched against the exact Host header. Use <code class="font-mono">*</code> only in the global policy.
          </p>
          <div v-if="visibleSuggestions.length" class="flex flex-wrap gap-1.5 mt-2">
            <button
              v-for="suggestion in visibleSuggestions"
              :key="suggestion"
              type="button"
              class="px-1.5 py-0.5 rounded border border-border font-mono text-[10px] text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors duration-150"
              @click="host = suggestion"
            >
              {{ suggestion }}
            </button>
          </div>
        </div>

        <div class="flex items-start justify-between gap-4 rounded-md border border-border p-3">
          <div class="min-w-0">
            <div class="text-xs font-medium text-foreground">Proof-of-work challenge</div>
            <p class="mt-0.5 text-[11px] leading-snug text-muted-foreground">
              Serve HTTP 468 Altcha challenges for this host. Disable to fingerprint only.
            </p>
          </div>
          <Switch
            v-model:checked="powEnabled"
            aria-label="Enable proof-of-work for this host"
            data-testid="bot-pow-toggle"
          />
        </div>

        <div :class="{ 'opacity-50 pointer-events-none': !powEnabled }">
          <div class="flex items-baseline justify-between mb-1">
            <label class="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground">
              PoW difficulty
            </label>
            <span class="text-[10px] font-mono text-muted-foreground">
              1,000 – 200,000 iterations
            </span>
          </div>
          <NumberInput
            v-model="difficulty"
            :min="MIN_DIFFICULTY"
            :max="MAX_DIFFICULTY"
            :step="1000"
            suffix="iters"
            data-testid="bot-difficulty-input"
          />
          <p v-if="difficultyInvalid" class="mt-1 text-[10px] text-warning">
            Enter a value between 1,000 and 200,000.
          </p>
        </div>

        <div>
          <label class="block mb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground">
            Trap URLs
          </label>
          <textarea
            v-model="trapsText"
            rows="3"
            placeholder="/.raiwall/trap/honeypot&#10;/admin/login.php"
            class="w-full rounded-md border border-input bg-card px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground shadow-none focus-visible:outline-none focus-visible:border-primary transition-colors resize-y"
            data-testid="bot-traps-input"
          />
          <p class="mt-1 text-[10px] text-muted-foreground">
            One path per line. Each must start with <code class="font-mono">/</code>. Hits are banned immediately.
          </p>
        </div>

        <div class="flex items-center justify-between rounded-md border border-border p-3">
          <div>
            <div class="text-xs font-medium text-foreground">Override active</div>
            <p class="mt-0.5 text-[11px] text-muted-foreground">
              Paused overrides stay configured but fall back to the global policy.
            </p>
          </div>
          <Switch
            v-model:checked="active"
            aria-label="Activate this host override"
            data-testid="bot-active-toggle"
          />
        </div>

        <div
          v-if="localError || error"
          class="flex items-start gap-2 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-[11px] text-threat"
          role="alert"
        >
          <ShieldAlert class="w-3.5 h-3.5 mt-px shrink-0" />
          <span>{{ localError || error }}</span>
        </div>
      </div>

      <DialogFooter class="gap-2">
        <Button variant="outline" size="sm" data-testid="bot-cancel-host" @click="emit('close')">
          Cancel
        </Button>
        <Button
          size="sm"
          class="gap-1.5 font-semibold uppercase tracking-wider"
          :disabled="saving"
          data-testid="bot-save-host"
          @click="handleSave"
        >
          <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
          <Save v-else class="w-3.5 h-3.5" />
          <span>{{ saving ? 'Saving' : 'Save Override' }}</span>
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
