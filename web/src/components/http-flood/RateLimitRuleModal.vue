<script setup lang="ts">
import { ref, computed, watch } from 'vue';
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
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';

export type LimitTierType = 'access' | 'attack' | 'error';

export interface RuleFormData {
  name: string;
  threshold: number;
  window_seconds: number;
  action: 'challenge' | 'block';
  duration_minutes: number;
}

const props = defineProps<{
  open: boolean;
  tier: LimitTierType;
  initialData?: Partial<RuleFormData>;
}>();

const emit = defineEmits<{
  (e: 'update:open', val: boolean): void;
  (e: 'save', data: { tier: LimitTierType; values: RuleFormData }): void;
}>();

const form = ref<RuleFormData>({
  name: 'Basic Access Limit',
  threshold: 100,
  window_seconds: 10,
  action: 'challenge',
  duration_minutes: 60,
});

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      if (props.tier === 'access') {
        form.value = {
          name: props.initialData?.name || 'Basic Access Limit',
          threshold: props.initialData?.threshold ?? 100,
          window_seconds: props.initialData?.window_seconds ?? 10,
          action: props.initialData?.action || 'challenge',
          duration_minutes: props.initialData?.duration_minutes ?? 60,
        };
      } else if (props.tier === 'attack') {
        form.value = {
          name: props.initialData?.name || 'Basic Attack Limit',
          threshold: props.initialData?.threshold ?? 10,
          window_seconds: props.initialData?.window_seconds ?? 60,
          action: 'block',
          duration_minutes: props.initialData?.duration_minutes ?? 30,
        };
      } else {
        form.value = {
          name: props.initialData?.name || 'Basic Error Limit',
          threshold: props.initialData?.threshold ?? 10,
          window_seconds: props.initialData?.window_seconds ?? 10,
          action: 'block',
          duration_minutes: props.initialData?.duration_minutes ?? 30,
        };
      }
    }
  },
  { immediate: true }
);

const modalTitle = computed(() => {
  switch (props.tier) {
    case 'access':
      return 'Edit Access Limiting Rule';
    case 'attack':
      return 'Edit Attack Limiting Rule';
    case 'error':
      return 'Edit Error Limiting Rule';
    default:
      return 'Edit Rate Limiting Rule';
  }
});

const generatedSentence = computed(() => {
  const reqStr = `${form.value.threshold} requests`;
  const winStr = `${form.value.window_seconds} seconds`;
  const actStr =
    form.value.action === 'challenge'
      ? 'require Anti-Bot challenge'
      : 'be automatically blocked';
  const durStr = `${form.value.duration_minutes} minutes`;

  if (props.tier === 'access') {
    return `An IP that makes ${reqStr} within ${winStr} will ${actStr} when accessing again within the next ${durStr}.`;
  } else if (props.tier === 'attack') {
    return `An IP that triggers attack blocking ${form.value.threshold} times within ${winStr} will be automatically blocked ${durStr}.`;
  } else {
    return `An IP that triggers 403, 404 errors ${form.value.threshold} times within ${winStr} will be automatically blocked for ${durStr}.`;
  }
});

const handleSave = () => {
  emit('save', { tier: props.tier, values: { ...form.value } });
  emit('update:open', false);
};

const handleClose = () => {
  emit('update:open', false);
};
</script>

<template>
  <Dialog :open="open" @update:open="(val) => emit('update:open', val)">
    <DialogContent class="sm:max-w-lg bg-card text-foreground border-border">
      <DialogHeader>
        <DialogTitle class="text-base font-semibold text-foreground">
          {{ modalTitle }}
        </DialogTitle>
        <DialogDescription class="text-xs text-muted-foreground">
          Configure volumetric defense threshold, evaluation interval, and mitigation enforcement.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2">
        <!-- Natural Language Preview Box -->
        <div class="p-3 bg-muted/50 rounded-lg border border-border/80">
          <span class="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground block mb-1">
            Rule Preview
          </span>
          <p class="text-xs font-medium text-foreground leading-relaxed">
            {{ generatedSentence }}
          </p>
        </div>

        <!-- Rule Name -->
        <div class="space-y-1.5">
          <label class="text-xs font-medium text-foreground block">Rule Name</label>
          <Input v-model="form.name" class="h-8 text-xs" />
        </div>

        <!-- Threshold and Window -->
        <div class="grid grid-cols-2 gap-3">
          <div class="space-y-1.5">
            <label class="text-xs font-medium text-foreground block">
              {{ tier === 'access' ? 'Requests Threshold' : tier === 'attack' ? 'Violations Threshold' : 'Errors Threshold' }}
            </label>
            <NumberInput
              v-model="form.threshold"
              :min="1"
              :suffix="tier === 'access' ? 'reqs' : tier === 'attack' ? 'pts' : 'errs'"
              class="h-8 text-xs font-mono shadow-none"
            />
          </div>
          <div class="space-y-1.5">
            <label class="text-xs font-medium text-foreground block">Window (Seconds)</label>
            <NumberInput
              v-model="form.window_seconds"
              :min="1"
              suffix="sec"
              class="h-8 text-xs font-mono shadow-none"
            />
          </div>
        </div>

        <!-- Action and Duration -->
        <div class="grid grid-cols-2 gap-3">
          <div class="space-y-1.5">
            <label class="text-xs font-medium text-foreground block">Enforced Action</label>
            <Select v-model="form.action">
              <SelectTrigger class="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="challenge">Anti-Bot Challenge</SelectItem>
                <SelectItem value="block">Automatic Block</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div class="space-y-1.5">
            <label class="text-xs font-medium text-foreground block">Duration (Minutes)</label>
            <NumberInput
              v-model="form.duration_minutes"
              :min="1"
              suffix="min"
              class="h-8 text-xs font-mono shadow-none"
            />
          </div>
        </div>
      </div>

      <DialogFooter class="flex items-center justify-end gap-2 pt-2 border-t border-border">
        <Button variant="outline" size="sm" class="h-8 text-xs" @click="handleClose">
          Cancel
        </Button>
        <Button size="sm" class="h-8 text-xs font-semibold" @click="handleSave">
          Save Changes
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
