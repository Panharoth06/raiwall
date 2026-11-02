<script setup lang="ts">
import { computed } from 'vue';
import type { ResponseMode, ResponsePolicy } from '@/api/detection';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { NumberInput } from '@/components/ui/number-input';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { FileSearch, KeyRound } from 'lucide-vue-next';

const props = defineProps<{
  modelValue?: ResponsePolicy;
  canEdit?: boolean;
  saving?: boolean;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: ResponsePolicy];
}>();

const policy = computed<ResponsePolicy>(() => props.modelValue ?? {});

const isEnabled = computed(() => policy.value.enabled ?? false);
const responseMode = computed(() => policy.value.mode ?? 'inherit');
const inspectHeaders = computed(() => policy.value.inspect_headers ?? true);
const inspectBody = computed(() => policy.value.inspect_body ?? true);
const bodyLimitKiB = computed(() => Math.round((policy.value.body_limit ?? 1048576) / 1024));

const dlpEnabled = computed(() => policy.value.dlp?.enabled ?? false);
const dlpAction = computed(() => policy.value.dlp?.action ?? 'inherit');
const detectPAN = computed(() => policy.value.dlp?.detect_pan ?? true);
const detectSecrets = computed(() => policy.value.dlp?.detect_secrets ?? true);
const detectJWT = computed(() => policy.value.dlp?.detect_jwt ?? true);
const detectPrivateKeys = computed(() => policy.value.dlp?.detect_private_keys ?? true);
const redactionMask = computed(() => policy.value.dlp?.redaction ?? '[REDACTED]');

function update(patch: Partial<ResponsePolicy>) {
  emit('update:modelValue', {
    ...policy.value,
    ...patch,
  });
}

function updateDLP(patch: Partial<NonNullable<ResponsePolicy['dlp']>>) {
  emit('update:modelValue', {
    ...policy.value,
    dlp: {
      ...(policy.value.dlp ?? {}),
      ...patch,
    },
  });
}

const modeOptions: { value: ResponseMode; label: string }[] = [
  { value: 'inherit', label: 'Inherit Default' },
  { value: 'audit', label: 'Audit (Log findings)' },
  { value: 'redact', label: 'Redact (Mask sensitive data)' },
  { value: 'block', label: 'Block (Return HTTP 403)' },
];
</script>

<template>
  <div class="rounded-lg border border-border bg-muted/30 p-3.5 space-y-3 font-sans">
    <div class="flex items-center justify-between gap-3">
      <div>
        <div class="flex items-center gap-2">
          <FileSearch class="w-4 h-4 text-primary" />
          <span class="text-xs font-semibold text-foreground">Outbound Inspection & DLP</span>
          <Badge
            variant="outline"
            class="text-xs uppercase font-mono tracking-wider border-border text-muted-foreground"
          >
            Data Loss Prevention
          </Badge>
        </div>
        <p class="text-xs text-muted-foreground mt-0.5">
          Deep-inspect upstream response headers and bodies before proxying back to clients.
        </p>
      </div>
      <Switch
        :checked="isEnabled"
        :disabled="!canEdit || saving"
        data-testid="response-inspection-toggle"
        @update:checked="(val) => update({ enabled: val })"
      />
    </div>

    <div v-if="isEnabled" class="space-y-3 pt-2 border-t border-border/60">
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <label class="space-y-1">
          <span class="text-xs text-muted-foreground">Response Mode</span>
          <Select
            :model-value="responseMode"
            @update:model-value="(val) => update({ mode: val as ResponseMode })"
          >
            <SelectTrigger
              class="h-8 text-xs bg-card border-border text-foreground"
              :disabled="!canEdit || saving"
              data-testid="response-mode-select"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent class="border-border bg-popover text-popover-foreground">
              <SelectItem
                v-for="opt in modeOptions"
                :key="opt.value"
                :value="opt.value"
                class="text-xs"
              >
                {{ opt.label }}
              </SelectItem>
            </SelectContent>
          </Select>
        </label>

        <label class="space-y-1">
          <span class="text-xs text-muted-foreground">Body Limit (KiB)</span>
          <NumberInput
            :model-value="bodyLimitKiB"
            :min="1"
            :max="8192"
            :disabled="!canEdit || saving"
            input-class="h-8 text-xs font-mono"
            data-testid="response-body-limit"
            @update:model-value="(val) => update({ body_limit: (Number(val) || 1024) * 1024 })"
          />
        </label>

        <div class="flex items-center gap-4 pt-4">
          <label class="flex items-center gap-2 cursor-pointer">
            <Switch
              :checked="inspectHeaders"
              :disabled="!canEdit || saving"
              data-testid="response-inspect-headers"
              @update:checked="(val) => update({ inspect_headers: val })"
            />
            <span class="text-xs text-foreground">Inspect Headers</span>
          </label>

          <label class="flex items-center gap-2 cursor-pointer">
            <Switch
              :checked="inspectBody"
              :disabled="!canEdit || saving"
              data-testid="response-inspect-body"
              @update:checked="(val) => update({ inspect_body: val })"
            />
            <span class="text-xs text-foreground">Inspect Body</span>
          </label>
        </div>
      </div>

      <!-- DLP Pattern Detectors -->
      <div class="rounded-md border border-border bg-card p-3 space-y-2.5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <KeyRound class="w-3.5 h-3.5 text-primary" />
            <span class="text-xs font-semibold text-foreground">Sensitive Pattern Detectors</span>
          </div>
          <Switch
            :checked="dlpEnabled"
            :disabled="!canEdit || saving"
            data-testid="dlp-toggle"
            @update:checked="(val) => updateDLP({ enabled: val })"
          />
        </div>

        <div v-if="dlpEnabled" class="space-y-2.5 pt-1.5 border-t border-border/40">
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <label class="flex items-center gap-2 cursor-pointer">
              <Switch
                :checked="detectPAN"
                :disabled="!canEdit || saving"
                data-testid="dlp-pan-switch"
                @update:checked="(val) => updateDLP({ detect_pan: val })"
              />
              <span class="text-foreground">Credit Cards (PAN)</span>
            </label>

            <label class="flex items-center gap-2 cursor-pointer">
              <Switch
                :checked="detectSecrets"
                :disabled="!canEdit || saving"
                data-testid="dlp-secrets-switch"
                @update:checked="(val) => updateDLP({ detect_secrets: val })"
              />
              <span class="text-foreground">API Keys / Tokens</span>
            </label>

            <label class="flex items-center gap-2 cursor-pointer">
              <Switch
                :checked="detectJWT"
                :disabled="!canEdit || saving"
                data-testid="dlp-jwt-switch"
                @update:checked="(val) => updateDLP({ detect_jwt: val })"
              />
              <span class="text-foreground">JWT Tokens</span>
            </label>

            <label class="flex items-center gap-2 cursor-pointer">
              <Switch
                :checked="detectPrivateKeys"
                :disabled="!canEdit || saving"
                data-testid="dlp-private-keys-switch"
                @update:checked="(val) => updateDLP({ detect_private_keys: val })"
              />
              <span class="text-foreground">Private Keys</span>
            </label>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-border/40">
            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">DLP Action</span>
              <Select
                :model-value="dlpAction"
                @update:model-value="(val) => updateDLP({ action: val as ResponseMode })"
              >
                <SelectTrigger
                  class="h-8 text-xs bg-card border-border text-foreground"
                  :disabled="!canEdit || saving"
                  data-testid="dlp-action-select"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent class="border-border bg-popover text-popover-foreground">
                  <SelectItem
                    v-for="opt in modeOptions"
                    :key="opt.value"
                    :value="opt.value"
                    class="text-xs"
                  >
                    {{ opt.label }}
                  </SelectItem>
                </SelectContent>
              </Select>
            </label>

            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">Redaction Mask</span>
              <Input
                :model-value="redactionMask"
                :disabled="!canEdit || saving"
                class="h-8 text-xs font-mono"
                data-testid="dlp-redaction-input"
                placeholder="[REDACTED]"
                @update:model-value="(val) => updateDLP({ redaction: String(val) })"
              />
            </label>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
