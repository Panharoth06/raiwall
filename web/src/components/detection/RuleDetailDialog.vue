<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { DetectionRule, RuleOverride } from '@/api/detection';
import { useAuthStore } from '@/stores/auth';
import AdminOnly from '@/components/auth/AdminOnly.vue';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Loader2, RotateCcw, Save } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  rule: DetectionRule | null;
  saving?: boolean;
}>();

const emit = defineEmits<{
  close: [];
  save: [rule: DetectionRule, override: RuleOverride];
  reset: [rule: DetectionRule];
}>();

const auth = useAuthStore();
const canEdit = computed(() => auth.user?.role !== 'viewer');

const enabled = ref(true);
const action = ref('inherit');
const severity = ref('');

watch(
  () => props.rule,
  (rule) => {
    enabled.value = rule?.enabled ?? true;
    action.value = rule?.action ?? 'inherit';
    severity.value = rule?.severity ?? '';
  },
  { immediate: true }
);

const actionOptions = [
  { value: 'inherit', label: 'Inherit source default' },
  { value: 'block', label: 'Block' },
  { value: 'alert', label: 'Alert only' },
  { value: 'off', label: 'Off (remove)' },
];

const severityOptions = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const save = () => {
  if (!props.rule) return;
  emit('save', props.rule, {
    enabled: enabled.value,
    action: action.value,
    severity: severity.value,
  });
};
</script>

<template>
  <Dialog :open="open" @update:open="(value) => { if (!value) emit('close'); }">
    <DialogContent class="sm:max-w-xl bg-card border-border">
      <DialogHeader>
        <DialogTitle class="text-base font-semibold text-foreground flex items-center gap-2 min-w-0">
          <span class="truncate">{{ rule?.name || 'Rule details' }}</span>
          <Badge v-if="rule?.overridden" variant="outline" class="border-warning/30 bg-warning/10 text-warning">
            OVERRIDDEN
          </Badge>
        </DialogTitle>
        <DialogDescription class="font-mono text-xs text-muted-foreground truncate">
          {{ rule?.id }}
        </DialogDescription>
      </DialogHeader>

      <div v-if="rule" class="space-y-4">
        <div class="flex flex-wrap items-center gap-2">
          <Badge variant="outline" class="font-mono text-xs">{{ rule.source }}</Badge>
          <Badge variant="outline" class="font-mono text-xs">{{ rule.category }}</Badge>
          <Badge variant="outline" class="font-mono text-xs">{{ rule.severity.toUpperCase() }}</Badge>
          <Badge v-if="rule.phase" variant="outline" class="font-mono text-xs">PHASE {{ rule.phase }}</Badge>
          <Badge v-if="rule.pack_name" variant="outline" class="font-mono text-xs max-w-56 truncate">
            {{ rule.pack_name }}
          </Badge>
        </div>

        <p class="text-sm text-muted-foreground leading-relaxed">
          {{ rule.description || 'No description is available for this rule.' }}
        </p>

        <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
          <div>
            <dt class="text-muted-foreground">Default action</dt>
            <dd class="font-mono text-foreground">{{ rule.default_action }}</dd>
          </div>
          <div>
            <dt class="text-muted-foreground">Default severity</dt>
            <dd class="font-mono text-foreground">{{ rule.default_severity }}</dd>
          </div>
          <div v-if="rule.methods?.length">
            <dt class="text-muted-foreground">Methods</dt>
            <dd class="font-mono text-foreground">{{ rule.methods.join(', ') }}</dd>
          </div>
          <div v-if="rule.prefix">
            <dt class="text-muted-foreground">Path scope</dt>
            <dd class="font-mono text-foreground truncate">{{ rule.prefix }}</dd>
          </div>
        </dl>

        <div class="rounded-md border border-border bg-muted/20 p-3 space-y-3">
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-foreground">Enabled</p>
              <p class="text-xs text-muted-foreground">Disabled rules are removed from the engine.</p>
            </div>
            <Switch
              :checked="enabled"
              :disabled="!canEdit || saving"
              data-testid="rule-detail-enabled"
              @update:checked="(value) => (enabled = value)"
            />
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">Action</span>
              <Select
                :model-value="action"
                @update:model-value="(value) => (action = String(value))"
              >
                <SelectTrigger
                  class="h-8 text-xs bg-background border-input"
                  :disabled="!canEdit || saving"
                  data-testid="rule-detail-action"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent class="border-border bg-popover text-popover-foreground">
                  <SelectItem v-for="option in actionOptions" :key="option.value" :value="option.value" class="text-xs">
                    {{ option.label }}
                  </SelectItem>
                </SelectContent>
              </Select>
            </label>

            <label class="space-y-1">
              <span class="text-xs text-muted-foreground">Severity</span>
              <Select
                :model-value="severity"
                @update:model-value="(value) => (severity = String(value))"
              >
                <SelectTrigger
                  class="h-8 text-xs bg-background border-input"
                  :disabled="!canEdit || saving"
                  data-testid="rule-detail-severity"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent class="border-border bg-popover text-popover-foreground">
                  <SelectItem v-for="option in severityOptions" :key="option.value" :value="option.value" class="text-xs">
                    {{ option.label }}
                  </SelectItem>
                </SelectContent>
              </Select>
            </label>
          </div>
        </div>
      </div>

      <DialogFooter class="flex sm:justify-between gap-2 pt-4">
        <AdminOnly>
          <Button
            v-if="rule?.overridden"
            variant="outline"
            size="sm"
            class="gap-1.5"
            :disabled="saving"
            data-testid="rule-detail-reset"
            @click="rule && emit('reset', rule)"
          >
            <RotateCcw class="w-3.5 h-3.5" />
            <span>Reset override</span>
          </Button>
        </AdminOnly>
        <div class="flex items-center gap-2 ml-auto">
          <Button variant="outline" size="sm" :disabled="saving" @click="emit('close')">
            Close
          </Button>
          <AdminOnly>
            <Button
              size="sm"
              class="gap-1.5"
              :disabled="saving || !canEdit"
              data-testid="rule-detail-save"
              @click="save"
            >
              <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
              <Save v-else class="w-3.5 h-3.5" />
              <span>{{ saving ? 'Saving…' : 'Save override' }}</span>
            </Button>
          </AdminOnly>
        </div>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
