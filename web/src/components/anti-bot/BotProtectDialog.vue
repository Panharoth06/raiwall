<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { BotConfig } from '@/api/bot';
import type { BotPolicyDraft, BotPolicyTarget } from '@/composables/useAntiBot';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Bot, Fingerprint, Ghost, Info, Loader2, RotateCcw, Save, ShieldAlert } from 'lucide-vue-next';

const MIN_DIFFICULTY = 1_000;
const MAX_DIFFICULTY = 200_000;
const DEFAULT_DIFFICULTY = 50_000;
/** Altcha measures difficulty in iterations; ~50k solves in ~150ms on a mid-range browser. */
const ITERATIONS_PER_150MS = 50_000;

const presets = [
  { value: 20_000, label: 'Low' },
  { value: 50_000, label: 'Balanced' },
  { value: 100_000, label: 'Aggressive' },
];

const props = defineProps<{
  open: boolean;
  target: BotPolicyTarget | null;
  config?: BotConfig | null;
  inherited?: boolean;
  custom?: boolean;
  saving?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', draft: BotPolicyDraft): void;
  (e: 'reset'): void;
}>();

const powEnabled = ref(true);
const difficulty = ref(DEFAULT_DIFFICULTY);
const trapsEnabled = ref(false);
const trapsText = ref('');
const localError = ref('');

const scopeLabel = computed(() => {
  if (!props.target) return '';
  if (props.target.global) return 'All hosts without an application policy';
  const hosts = props.target.hostnames;
  return hosts.length ? hosts.join(' · ') : 'No hostnames configured';
});

const difficultyLabel = computed(() => difficulty.value.toLocaleString('en-US'));
const estimatedSolveMs = computed(() =>
  Math.round((difficulty.value / ITERATIONS_PER_150MS) * 150)
);
const canReset = computed(() => Boolean(props.custom && !props.target?.global));

function reset() {
  const config = props.config;
  powEnabled.value = config?.pow_enabled ?? true;
  const storedDifficulty = config?.pow_difficulty || DEFAULT_DIFFICULTY;
  difficulty.value = Math.min(Math.max(storedDifficulty, MIN_DIFFICULTY), MAX_DIFFICULTY);
  trapsEnabled.value = (config?.trap_urls?.length ?? 0) > 0;
  trapsText.value = (config?.trap_urls ?? []).join('\n');
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
  const value = difficulty.value;

  if (powEnabled.value && (value < MIN_DIFFICULTY || value > MAX_DIFFICULTY)) {
    localError.value = `Difficulty must be between ${MIN_DIFFICULTY.toLocaleString()} and ${MAX_DIFFICULTY.toLocaleString()} iterations.`;
    return;
  }

  const traps = trapsEnabled.value
    ? trapsText.value
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
    : [];

  const invalidTrap = traps.find((trap) => !trap.startsWith('/'));
  if (invalidTrap) {
    localError.value = `Trap URL "${invalidTrap}" must start with /.`;
    return;
  }

  emit('save', {
    pow_enabled: powEnabled.value,
    pow_difficulty: value,
    trap_urls: traps,
    // Saving from BOT Protect always (re)activates the policy for this scope.
    is_active: true,
  });
}
</script>

<template>
  <Dialog :open="open" @update:open="(value) => !value && emit('close')">
    <DialogContent class="max-w-xl max-h-[88vh] overflow-y-auto" data-testid="bot-protect-dialog">
      <DialogHeader>
        <div class="flex items-center gap-2.5">
          <Bot class="w-5 h-5 text-muted-foreground" />
          <DialogTitle class="text-base font-semibold">BOT Protect</DialogTitle>
          <Badge v-if="target?.global" variant="outline" class="font-mono text-xs uppercase">
            global
          </Badge>
        </div>
        <DialogDescription class="text-xs text-muted-foreground">
          <span class="font-medium text-foreground">{{ target?.name }}</span>
          <span class="mx-1.5 text-border">/</span>
          <span class="font-mono break-all">{{ scopeLabel }}</span>
        </DialogDescription>
      </DialogHeader>

      <div
        v-if="inherited && !target?.global"
        class="flex items-start gap-2 rounded-md border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground"
        data-testid="bot-inherited-note"
      >
        <Info class="w-3.5 h-3.5 mt-px shrink-0" />
        <span>
          This application inherits the global policy. Saving creates an application-scoped
          override for every hostname listed above.
        </span>
      </div>

      <div class="space-y-3 py-1">
        <!-- Anti-Bot Challenge -->
        <section class="rounded-md border border-border">
          <div class="flex items-start justify-between gap-4 p-3">
            <div class="min-w-0">
              <div class="flex items-center gap-1.5">
                <Fingerprint class="w-3.5 h-3.5 text-muted-foreground" />
                <h3 class="text-sm font-semibold text-foreground">Anti-Bot Challenge</h3>
              </div>
              <p class="mt-0.5 text-xs leading-snug text-muted-foreground">
                Automated browsers will be blocked when Anti-Bot is on. Humans solve a stateless
                SHA-256 proof-of-work and receive a clearance cookie.
              </p>
            </div>
            <Switch
              v-model:checked="powEnabled"
              aria-label="Enable Anti-Bot Challenge"
              data-testid="bot-challenge-toggle"
            />
          </div>

          <div v-if="powEnabled" class="border-t border-border/60 px-3 py-3 space-y-2">
            <div class="flex items-baseline justify-between gap-3">
              <label
                for="bot-protect-difficulty"
                class="text-xs font-mono font-semibold uppercase tracking-wider text-muted-foreground"
              >
                PoW difficulty
              </label>
              <span class="font-mono text-xs text-foreground tabular-nums">
                {{ difficultyLabel }}
                <span class="text-muted-foreground">iters · ≈{{ estimatedSolveMs }}ms</span>
              </span>
            </div>

            <input
              id="bot-protect-difficulty"
              type="range"
              :min="MIN_DIFFICULTY"
              :max="MAX_DIFFICULTY"
              step="5000"
              v-model.number="difficulty"
              class="w-full accent-primary cursor-pointer"
              data-testid="bot-difficulty-slider"
            />

            <div class="flex flex-wrap items-center gap-1.5">
              <button
                v-for="preset in presets"
                :key="preset.value"
                type="button"
                class="px-2 py-1 rounded border text-xs font-mono uppercase tracking-wider transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                :class="
                  difficulty === preset.value
                    ? 'border-primary text-foreground bg-primary/5'
                    : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/60'
                "
                :data-testid="`bot-difficulty-preset-${preset.value}`"
                @click="difficulty = preset.value"
              >
                {{ preset.label }}
              </button>
              <span class="ml-auto text-xs font-mono text-muted-foreground">
                {{ MIN_DIFFICULTY.toLocaleString() }} – {{ MAX_DIFFICULTY.toLocaleString() }}
              </span>
            </div>
          </div>
        </section>

        <!-- Crawler Trap -->
        <section class="rounded-md border border-border">
          <div class="flex items-start justify-between gap-4 p-3">
            <div class="min-w-0">
              <div class="flex items-center gap-1.5">
                <Ghost class="w-3.5 h-3.5 text-muted-foreground" />
                <h3 class="text-sm font-semibold text-foreground">Crawler Trap</h3>
              </div>
              <p class="mt-0.5 text-xs leading-snug text-muted-foreground">
                Invisible trap paths. Any client that requests one is banned immediately, even when
                no challenge was served.
              </p>
            </div>
            <Switch
              v-model:checked="trapsEnabled"
              aria-label="Enable crawler traps"
              data-testid="bot-trap-toggle"
            />
          </div>

          <div v-if="trapsEnabled" class="border-t border-border/60 px-3 py-3">
            <label
              for="bot-protect-traps"
              class="block mb-1 text-xs font-mono font-semibold uppercase tracking-wider text-muted-foreground"
            >
              Trap URLs
            </label>
            <textarea
              id="bot-protect-traps"
              v-model="trapsText"
              rows="3"
              placeholder="/.raiwall/trap/honeypot&#10;/admin/login.php"
              class="w-full rounded-md border border-input bg-card px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground shadow-none focus-visible:outline-none focus-visible:border-primary transition-colors resize-y"
              data-testid="bot-traps-input"
            />
            <p class="mt-1 text-xs text-muted-foreground">
              One path per line. Each must start with <code class="font-mono">/</code>.
            </p>
          </div>
        </section>

        <div class="flex items-start gap-2 rounded-md border border-border/60 px-3 py-2 text-xs text-muted-foreground">
          <Info class="w-3.5 h-3.5 mt-px shrink-0" />
          <p class="leading-snug">
            Challenge bypass is automatic for
            <code class="font-mono text-foreground">Authorization: Bearer</code> requests,
            <code class="font-mono text-foreground">/api/*</code> routes, and
            <code class="font-mono text-foreground">Accept: application/json</code> clients.
          </p>
        </div>

        <div
          v-if="localError || error"
          class="flex items-start gap-2 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-xs text-threat"
          role="alert"
        >
          <ShieldAlert class="w-3.5 h-3.5 mt-px shrink-0" />
          <span>{{ localError || error }}</span>
        </div>
      </div>

      <DialogFooter class="gap-2 sm:justify-between">
        <Button
          v-if="canReset"
          variant="ghost"
          size="sm"
          class="gap-1.5 text-muted-foreground"
          :disabled="saving"
          data-testid="bot-reset-policy"
          @click="emit('reset')"
        >
          <RotateCcw class="w-3.5 h-3.5" />
          <span>Use global default</span>
        </Button>
        <div class="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" :disabled="saving" data-testid="bot-cancel-protect" @click="emit('close')">
            Cancel
          </Button>
          <Button
            size="sm"
            class="gap-1.5 font-semibold uppercase tracking-wider"
            :disabled="saving"
            data-testid="bot-save-protect"
            @click="handleSave"
          >
            <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
            <Save v-else class="w-3.5 h-3.5" />
            <span>{{ saving ? 'Saving' : 'Save' }}</span>
          </Button>
        </div>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
