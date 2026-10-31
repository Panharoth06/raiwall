<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { DetectionMode, Sensitivity, WAFPolicy } from '@/api/detection';
import { useAuthStore } from '@/stores/auth';
import AdminOnly from '@/components/auth/AdminOnly.vue';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { NumberInput } from '@/components/ui/number-input';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import {
  Check,
  ChevronDown,
  Eye,
  Loader2,
  Save,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Sliders,
  Sparkles,
} from 'lucide-vue-next';

const props = defineProps<{
  policy: WAFPolicy;
  saving?: boolean;
}>();

const emit = defineEmits<{
  save: [policy: WAFPolicy];
}>();

const auth = useAuthStore();
const canEdit = computed(() => auth.user?.role !== 'viewer');

const modes: { value: DetectionMode; label: string; description: string }[] = [
  { value: 'inherit', label: 'Inherit', description: 'Use the application run mode.' },
  { value: 'off', label: 'Off', description: 'Skip WAF inspection for this scope.' },
  { value: 'alert', label: 'Alert', description: 'Record detections without blocking.' },
  { value: 'block', label: 'Block', description: 'Enforce blocking verdicts.' },
];

const sensitivityOptions: { value: Sensitivity; label: string }[] = [
  { value: 'inherit', label: 'Inherit process default' },
  { value: 'low', label: 'Low — high-confidence only' },
  { value: 'medium', label: 'Medium — balanced triage' },
  { value: 'high', label: 'High — strict on every signal' },
];

const mode = ref<DetectionMode>('inherit');
const sensitivity = ref<Sensitivity>('inherit');
const crsEnabled = ref(false);
const paranoia = ref(1);
const inbound = ref(5);
const outbound = ref(4);
const showAdvanced = ref(false);

watch(
  () => props.policy,
  (next) => {
    // Global detection policy defaults to Balanced Defense (block + medium)
    mode.value = (next.detection_mode && next.detection_mode !== 'inherit') ? next.detection_mode : 'block';
    sensitivity.value = (next.sensitivity && next.sensitivity !== 'inherit') ? next.sensitivity : 'medium';
    crsEnabled.value = next.crs?.enabled ?? true;
    paranoia.value = next.crs?.paranoia_level ?? 1;
    inbound.value = next.crs?.inbound_threshold ?? 5;
    outbound.value = next.crs?.outbound_threshold ?? 4;
  },
  { deep: true, immediate: true }
);

const modeDescription = computed(
  () => modes.find((entry) => entry.value === mode.value)?.description ?? ''
);

const sensitivitySummary = computed(() => {
  switch (sensitivity.value) {
    case 'low':
      return 'Logic/protocol heuristics audit; CRS PL1, thresholds 10/8.';
    case 'medium':
      return 'All modules balance confident matches; CRS PL1, thresholds 5/4.';
    case 'high':
      return 'All modules strict; CRS PL2, thresholds 3/2.';
    default:
      return 'No preset override; the process default matrix applies.';
  }
});

// Human-friendly Presets
const isStrictSelected = computed(() => {
  return mode.value === 'block' && sensitivity.value === 'high' && paranoia.value >= 2;
});

const isAuditSelected = computed(() => {
  return mode.value === 'alert';
});

const isOffSelected = computed(() => {
  return mode.value === 'off';
});

const isBalancedSelected = computed(() => {
  // Balanced Defense is selected by default unless user switches to Strict, Monitoring, or Off
  return !isStrictSelected.value && !isAuditSelected.value && !isOffSelected.value;
});

const applyPreset = (preset: 'balanced' | 'strict' | 'audit' | 'off') => {
  if (!canEdit.value || props.saving) return;
  switch (preset) {
    case 'balanced':
      mode.value = 'block';
      sensitivity.value = 'medium';
      crsEnabled.value = true;
      paranoia.value = 1;
      inbound.value = 5;
      outbound.value = 4;
      break;
    case 'strict':
      mode.value = 'block';
      sensitivity.value = 'high';
      crsEnabled.value = true;
      paranoia.value = 2;
      inbound.value = 3;
      outbound.value = 2;
      break;
    case 'audit':
      mode.value = 'alert';
      sensitivity.value = 'medium';
      crsEnabled.value = true;
      paranoia.value = 1;
      inbound.value = 5;
      outbound.value = 4;
      break;
    case 'off':
      mode.value = 'off';
      sensitivity.value = 'low';
      crsEnabled.value = false;
      break;
  }
};

const save = () => {
  emit('save', {
    detection_mode: mode.value,
    sensitivity: sensitivity.value,
    semantic_overrides: props.policy.semantic_overrides,
    disabled_packs: props.policy.disabled_packs,
    crs: {
      enabled: crsEnabled.value,
      paranoia_level: paranoia.value,
      inbound_threshold: inbound.value,
      outbound_threshold: outbound.value,
    },
  });
};
</script>

<template>
  <div class="space-y-4 font-sans">
    <!-- Visual Beginner-Friendly Protection Level Presets -->
    <div class="space-y-2">
      <div class="flex items-center justify-between">
        <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Choose Protection Posture
        </label>
        <span class="text-xs text-muted-foreground">Click a preset to configure your security posture</span>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
        <!-- Preset 1: Balanced (Recommended) -->
        <div
          class="p-3.5 rounded-xl border text-left transition-all cursor-pointer relative flex flex-col justify-between"
          :class="isBalancedSelected ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border bg-card hover:bg-muted/40'"
          data-testid="preset-balanced"
          @click="applyPreset('balanced')"
        >
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <div class="flex items-center gap-2">
                <ShieldCheck class="w-4 h-4 text-primary" />
                <span class="text-xs font-semibold text-foreground">Balanced Defense</span>
              </div>
              <Badge variant="outline" class="font-mono text-xs uppercase border-primary/40 text-primary bg-primary/10">
                Recommended
              </Badge>
            </div>
            <p class="text-xs text-muted-foreground leading-relaxed">
              Auto-blocks SQL injection, XSS, and verified CVE exploits with minimal false alarms. Best for 99% of web apps.
            </p>
          </div>
          <div v-if="isBalancedSelected" class="mt-2 pt-2 border-t border-primary/20 flex items-center gap-1.5 text-xs text-primary font-medium">
            <Check class="w-3.5 h-3.5" />
            <span>Active Posture</span>
          </div>
        </div>

        <!-- Preset 2: Strict Security -->
        <div
          class="p-3.5 rounded-xl border text-left transition-all cursor-pointer relative flex flex-col justify-between"
          :class="isStrictSelected ? 'border-threat bg-threat/5 ring-1 ring-threat' : 'border-border bg-card hover:bg-muted/40'"
          data-testid="preset-strict"
          @click="applyPreset('strict')"
        >
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <div class="flex items-center gap-2">
                <ShieldAlert class="w-4 h-4 text-threat" />
                <span class="text-xs font-semibold text-foreground">Strict Defense</span>
              </div>
              <Badge variant="outline" class="font-mono text-xs uppercase border-threat/40 text-threat bg-threat/10">
                High Security
              </Badge>
            </div>
            <p class="text-xs text-muted-foreground leading-relaxed">
              Maximum security scanning across all heuristics. Ideal for checkout flows, banking, or during active attacks.
            </p>
          </div>
          <div v-if="isStrictSelected" class="mt-2 pt-2 border-t border-threat/20 flex items-center gap-1.5 text-xs text-threat font-medium">
            <Check class="w-3.5 h-3.5" />
            <span>Active Posture</span>
          </div>
        </div>

        <!-- Preset 3: Monitoring / Audit Mode -->
        <div
          class="p-3.5 rounded-xl border text-left transition-all cursor-pointer relative flex flex-col justify-between sm:col-span-2 lg:col-span-1"
          :class="isAuditSelected ? 'border-warning bg-warning/5 ring-1 ring-warning' : 'border-border bg-card hover:bg-muted/40'"
          data-testid="preset-audit"
          @click="applyPreset('audit')"
        >
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <div class="flex items-center gap-2">
                <Eye class="w-4 h-4 text-warning" />
                <span class="text-xs font-semibold text-foreground">Monitoring Mode</span>
              </div>
              <Badge variant="outline" class="font-mono text-xs uppercase border-warning/40 text-warning bg-warning/10">
                Non-blocking
              </Badge>
            </div>
            <p class="text-xs text-muted-foreground leading-relaxed">
              Logs all attack attempts in real-time telemetry without blocking any customer requests. Great for staging & testing.
            </p>
          </div>
          <div v-if="isAuditSelected" class="mt-2 pt-2 border-t border-warning/20 flex items-center gap-1.5 text-xs text-warning font-medium">
            <Check class="w-3.5 h-3.5" />
            <span>Active Posture</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Advanced Engine Accordion (Progressive Disclosure for Expert Engineers) -->
    <div class="rounded-xl border border-border bg-muted/20 overflow-hidden transition-all">
      <button
        type="button"
        class="w-full flex items-center justify-between px-4 py-2.5 text-left text-xs text-muted-foreground hover:text-foreground font-medium transition-colors cursor-pointer bg-card/50"
        @click="showAdvanced = !showAdvanced"
      >
        <div class="flex items-center gap-2">
          <Sliders class="w-3.5 h-3.5 text-primary" />
          <span class="font-semibold text-foreground">Advanced Engine Configuration</span>
          <span class="text-xs text-muted-foreground font-normal hidden sm:inline">— Paranoia levels, raw modes, anomaly thresholds</span>
        </div>
        <div class="flex items-center gap-1 text-xs">
          <span>{{ showAdvanced ? 'Hide' : 'Customize' }}</span>
          <ChevronDown class="w-3.5 h-3.5 transition-transform duration-200" :class="showAdvanced ? 'rotate-180' : ''" />
        </div>
      </button>

      <!-- Advanced Content (Always kept in DOM for programmatic test interaction) -->
      <div v-show="showAdvanced" class="p-4 space-y-4 border-t border-border bg-card">
        <!-- Raw Mode Selector -->
        <div class="space-y-1.5">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Detection Mode
            </span>
            <span class="text-xs text-muted-foreground">{{ modeDescription }}</span>
          </div>
          <div class="inline-flex items-center gap-1 rounded-md border border-border bg-muted/30 p-0.5">
            <Button
              v-for="entry in modes"
              :key="entry.value"
              size="sm"
              :variant="mode === entry.value ? 'default' : 'ghost'"
              class="h-7 px-2.5 text-xs"
              :disabled="!canEdit || saving"
              :data-testid="`detection-mode-${entry.value}`"
              @click="mode = entry.value"
            >
              {{ entry.label }}
            </Button>
          </div>
        </div>

        <!-- Sensitivity Preset Selector -->
        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pt-2 border-t border-border/60">
          <div class="min-w-0">
            <span class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Sensitivity Preset
            </span>
            <p class="text-xs text-muted-foreground mt-0.5">{{ sensitivitySummary }}</p>
          </div>
          <Select
            :model-value="sensitivity"
            @update:model-value="(value) => (sensitivity = value as Sensitivity)"
          >
            <SelectTrigger
              class="h-8 w-full sm:w-56 text-xs bg-card border-border text-foreground"
              :disabled="!canEdit || saving"
              data-testid="detection-sensitivity"
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
        </div>

        <!-- OWASP CRS Engine -->
        <div class="rounded-lg border border-border bg-muted/30 p-3 space-y-3">
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-xs font-semibold text-foreground">OWASP CRS Engine (Coraza SecRule)</p>
              <p class="text-xs text-muted-foreground">
                Evaluates ModSecurity Core Rule Set with cumulative anomaly scoring.
              </p>
            </div>
            <Switch
              :checked="crsEnabled"
              :disabled="!canEdit || saving"
              data-testid="detection-crs-enabled"
              @update:checked="(value) => (crsEnabled = value)"
            />
          </div>

          <div v-if="crsEnabled" class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 border-t border-border/60">
            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">Paranoia level</span>
              <NumberInput
                v-model="paranoia"
                :min="1"
                :max="4"
                :disabled="!canEdit || saving"
                input-class="h-8 text-xs font-mono"
                data-testid="detection-crs-pl"
              />
            </label>
            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">Inbound threshold</span>
              <NumberInput
                v-model="inbound"
                :min="0"
                :disabled="!canEdit || saving"
                input-class="h-8 text-xs font-mono"
                data-testid="detection-crs-inbound"
              />
            </label>
            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">Outbound threshold</span>
              <NumberInput
                v-model="outbound"
                :min="0"
                :disabled="!canEdit || saving"
                input-class="h-8 text-xs font-mono"
                data-testid="detection-crs-outbound"
              />
            </label>
          </div>
        </div>
      </div>
    </div>

    <!-- Save Action Bar -->
    <AdminOnly>
      <div class="flex items-center justify-end pt-2 border-t border-border">
        <Button
          size="sm"
          class="h-8 text-xs font-semibold gap-1.5"
          :disabled="!canEdit || saving"
          data-testid="detection-policy-save"
          @click="save"
        >
          <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
          <Save v-else class="w-3.5 h-3.5" />
          <span>{{ saving ? 'Applying…' : 'Apply Detection Policy' }}</span>
        </Button>
      </div>
    </AdminOnly>
  </div>
</template>
