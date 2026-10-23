<script setup lang="ts">
import { ref, watch } from 'vue';
import type { PolicySettings } from '@/api/client';
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
import { Plus, X, Layers, Sliders } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  policy: PolicySettings;
}>();

const emit = defineEmits<{
  (e: 'update:open', val: boolean): void;
  (e: 'save', val: PolicySettings): void;
}>();

const form = ref<{
  enabled: boolean;
  maxConcurrent: number;
  paths: string[];
}>({
  enabled: false,
  maxConcurrent: 1000,
  paths: [],
});

const newPathInput = ref('');

watch(
  () => props.policy,
  (p) => {
    if (p) {
      form.value = {
        enabled: !!p.waiting_room_enabled,
        maxConcurrent: p.waiting_room_max_concurrent || 1000,
        paths: [...(p.waiting_room_paths || [])],
      };
    }
  },
  { immediate: true }
);

const addPath = () => {
  const p = newPathInput.value.trim();
  if (!p) return;
  if (!form.value.paths.includes(p)) {
    form.value.paths.push(p);
  }
  newPathInput.value = '';
};

const removePath = (idx: number) => {
  form.value.paths.splice(idx, 1);
};

const handleSave = () => {
  emit('save', {
    ...props.policy,
    waiting_room_enabled: form.value.enabled,
    waiting_room_max_concurrent: form.value.maxConcurrent,
    waiting_room_paths: [...form.value.paths],
  });
  emit('update:open', false);
};
</script>

<template>
  <Dialog :open="open" @update:open="(val) => emit('update:open', val)">
    <DialogContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle class="flex items-center gap-2 text-sm font-semibold tracking-wide">
          <Sliders class="h-4 w-4 text-primary" />
          <span>Configure Virtual Waiting Room Engine (HTTP 465)</span>
        </DialogTitle>
        <DialogDescription class="text-xs text-muted-foreground">
          Configure active concurrency ceilings and targeted URL prefixes for traffic surges.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2">
        <!-- Enable/Disable Switch -->
        <div class="flex items-center justify-between p-3 border border-border rounded-lg bg-muted/20">
          <div>
            <div class="text-xs font-semibold text-foreground">Waiting Room Protection</div>
            <div class="text-[11px] text-muted-foreground mt-0.5">
              Serve HTTP 465 waiting queue pages when concurrency capacity is exceeded.
            </div>
          </div>
          <Switch
            :checked="form.enabled"
            @update:checked="(val) => form.enabled = val"
          />
        </div>

        <!-- Concurrency Capacity -->
        <div class="space-y-1.5">
          <label class="text-xs font-medium text-foreground">Active Concurrency Capacity</label>
          <NumberInput
            v-model="form.maxConcurrent"
            :min="1"
            :max="100000"
            suffix="users"
            class="h-8 font-mono text-xs"
          />
          <p class="text-[11px] text-muted-foreground">
            Maximum number of simultaneous active leases before incoming clients are queued.
          </p>
        </div>

        <!-- Targeted Path Prefixes -->
        <div class="space-y-2">
          <label class="text-xs font-medium text-foreground">Targeted Path Prefixes</label>
          <div class="flex items-center gap-2">
            <Input
              v-model="newPathInput"
              placeholder="e.g. /checkout, /tickets/*"
              class="h-8 text-xs font-mono"
              @keydown.enter.prevent="addPath"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              class="h-8 gap-1 text-xs shrink-0"
              @click="addPath"
            >
              <Plus class="h-3 w-3" />
              <span>Add Prefix</span>
            </Button>
          </div>

          <div class="flex flex-wrap gap-1.5 pt-1 min-h-[32px] p-2 rounded-md bg-muted/40 border border-border">
            <span
              v-if="form.paths.length === 0"
              class="text-[11px] text-muted-foreground italic flex items-center gap-1"
            >
              <Layers class="h-3 w-3" />
              <span>All paths targeted by default (/*)</span>
            </span>
            <span
              v-for="(p, idx) in form.paths"
              :key="idx"
              class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-background text-foreground border border-border text-[11px] font-mono"
            >
              <span>{{ p }}</span>
              <button
                type="button"
                class="text-muted-foreground hover:text-foreground"
                @click="removePath(idx)"
              >
                <X class="h-3 w-3" />
              </button>
            </span>
          </div>
        </div>
      </div>

      <DialogFooter>
        <Button variant="outline" size="sm" class="h-8 text-xs" @click="emit('update:open', false)">
          Cancel
        </Button>
        <Button size="sm" class="h-8 text-xs font-semibold" @click="handleSave">
          Save Configuration
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
