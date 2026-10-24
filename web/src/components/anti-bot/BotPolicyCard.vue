<script setup lang="ts">
import { computed } from 'vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  Fingerprint,
  Loader2,
  Save,
  ShieldCheck,
  Eye,
  Ghost,
  Info,
} from 'lucide-vue-next';

const props = defineProps<{
  powEnabled: boolean;
  difficulty: number;
  honeypot: boolean;
  saving?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:powEnabled', value: boolean): void;
  (e: 'update:difficulty', value: number): void;
  (e: 'update:honeypot', value: boolean): void;
  (e: 'save'): void;
}>();

/** Altcha measures difficulty as MaxNumber; ~50k iterations takes ~150ms in a browser. */
const ITERATIONS_PER_150MS = 50_000;

const issuanceOptions = [
  {
    value: false,
    label: 'Fingerprint only',
    consequence: 'Observes JA4 and bot signals. Serves no challenges.',
    icon: Eye,
    testId: 'pow-disabled',
  },
  {
    value: true,
    label: 'Challenge browsers',
    consequence: 'Serves HTTP 468 PoW to suspicious browser routes.',
    icon: ShieldCheck,
    testId: 'pow-enabled',
  },
];

const presets = [
  { value: 20_000, label: 'Low' },
  { value: 50_000, label: 'Balanced' },
  { value: 100_000, label: 'Aggressive' },
];

const difficultyLabel = computed(() => props.difficulty.toLocaleString('en-US'));
const estimatedSolveMs = computed(() =>
  Math.round((props.difficulty / ITERATIONS_PER_150MS) * 150)
);
</script>

<template>
  <div class="bg-card border border-border rounded-lg" data-testid="bot-policy-card">
    <div class="flex items-center justify-between gap-3 px-4 py-3 border-b border-border">
      <div class="flex items-center gap-2 min-w-0">
        <Fingerprint class="w-4 h-4 text-muted-foreground shrink-0" />
        <h2 class="text-xs font-semibold uppercase tracking-wider text-foreground truncate">
          Challenge Policy
        </h2>
        <Badge variant="outline" class="hidden sm:inline-flex font-mono uppercase text-[10px]">all hosts</Badge>
      </div>

      <Button
        size="sm"
        class="h-8 gap-1.5 text-[11px] font-semibold uppercase tracking-wider"
        :disabled="saving"
        data-testid="save-bot-policy"
        @click="emit('save')"
      >
        <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
        <Save v-else class="w-3.5 h-3.5" />
        <span class="sm:hidden">{{ saving ? 'Saving' : 'Save' }}</span>
        <span class="hidden sm:inline">{{ saving ? 'Saving' : 'Save Policy' }}</span>
      </Button>
    </div>

    <div class="p-4 grid grid-cols-1 lg:grid-cols-12 gap-4">
      <!-- PoW issuance -->
      <div class="lg:col-span-5 min-w-0">
        <div class="flex items-baseline justify-between mb-2">
          <label class="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground">
            PoW issuance
          </label>
          <span class="text-[10px] font-mono uppercase text-muted-foreground">
            {{ powEnabled ? 'enabled' : 'disabled' }}
          </span>
        </div>

        <div class="grid grid-cols-2 gap-2" role="radiogroup" aria-label="Proof-of-work issuance">
          <button
            v-for="option in issuanceOptions"
            :key="option.label"
            type="button"
            role="radio"
            :aria-checked="powEnabled === option.value"
            :data-testid="option.testId"
            class="text-left p-2.5 rounded-md border transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            :class="
              powEnabled === option.value
                ? 'border-primary bg-primary/5 text-foreground'
                : 'border-border bg-card text-muted-foreground hover:bg-muted/60 hover:text-foreground'
            "
            @click="emit('update:powEnabled', option.value)"
          >
            <span class="flex items-center gap-1.5">
              <component :is="option.icon" class="w-3.5 h-3.5 shrink-0" />
              <span class="text-xs font-semibold">{{ option.label }}</span>
              <span
                class="ml-auto w-2 h-2 rounded-full border"
                :class="powEnabled === option.value ? 'bg-primary border-primary' : 'border-border'"
              />
            </span>
            <span class="mt-1 block text-[11px] leading-snug text-muted-foreground">
              {{ option.consequence }}
            </span>
          </button>
        </div>
      </div>

      <!-- PoW difficulty -->
      <div class="lg:col-span-4 min-w-0">
        <div class="flex items-baseline justify-between mb-2">
          <label
            for="pow-difficulty"
            class="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground"
          >
            PoW difficulty
          </label>
          <span class="font-mono text-[11px] text-foreground tabular-nums">
            {{ difficultyLabel }}
            <span class="text-muted-foreground">iters · ≈{{ estimatedSolveMs }}ms</span>
          </span>
        </div>

        <input
          id="pow-difficulty"
          type="range"
          min="5000"
          max="100000"
          step="5000"
          :value="difficulty"
          :disabled="!powEnabled"
          class="w-full accent-primary cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="difficulty-slider"
          @input="emit('update:difficulty', Number(($event.target as HTMLInputElement).value))"
        />

        <div class="flex items-center gap-1.5 mt-2">
          <button
            v-for="preset in presets"
            :key="preset.value"
            type="button"
            class="px-2 py-1 rounded border text-[10px] font-mono uppercase tracking-wider transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-40"
            :class="
              difficulty === preset.value
                ? 'border-primary text-foreground bg-primary/5'
                : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/60'
            "
            :disabled="!powEnabled"
            :data-testid="`difficulty-preset-${preset.value}`"
            @click="emit('update:difficulty', preset.value)"
          >
            {{ preset.label }}
          </button>
        </div>
      </div>

      <!-- Honeypot -->
      <div class="lg:col-span-3 min-w-0 lg:border-l lg:border-border lg:pl-4">
        <label class="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted-foreground">
          Crawler trap
        </label>
        <div class="mt-2 flex items-start gap-2.5">
          <Switch
            :checked="honeypot"
            :disabled="!powEnabled"
            aria-label="Enable honeypot trap links"
            data-testid="honeypot-toggle"
            @update:checked="emit('update:honeypot', $event)"
          />
          <div class="min-w-0">
            <div class="flex items-center gap-1 text-xs font-medium text-foreground">
              <Ghost class="w-3.5 h-3.5 text-muted-foreground" />
              <span>Honeypot links</span>
            </div>
            <p class="mt-0.5 text-[11px] leading-snug text-muted-foreground">
              Injects invisible links. Crawlers that follow them are banned.
            </p>
          </div>
        </div>
      </div>
    </div>

    <div class="flex items-start gap-2 px-4 py-2 border-t border-border/60 text-[11px] text-muted-foreground">
      <Info class="w-3.5 h-3.5 mt-px shrink-0" />
      <p class="leading-snug">
        Challenge bypass is automatic for
        <code class="font-mono text-foreground">Authorization: Bearer</code> requests,
        <code class="font-mono text-foreground">/api/*</code> routes, and
        <code class="font-mono text-foreground">Accept: application/json</code> clients. Changes are staged to the
        config draft and activate on deploy.
      </p>
    </div>
  </div>
</template>
