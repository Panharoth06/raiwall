<script setup lang="ts">
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
import { Plus, Trash2, Info } from 'lucide-vue-next';
import type { LoadBalancing, RoutingType, UpstreamEntry } from './useSiteForm';

const routingType = defineModel<RoutingType>('routingType', { required: true });
const upstreams = defineModel<UpstreamEntry[]>('upstreams', { required: true });
const loadBalancing = defineModel<LoadBalancing>('loadBalancing', { required: true });
const documentRoot = defineModel<string>('documentRoot', { required: true });
const redirectUrl = defineModel<string>('redirectUrl', { required: true });
const redirectStatus = defineModel<number>('redirectStatus', { required: true });

const emit = defineEmits<{
  (e: 'add-upstream'): void;
  (e: 'remove-upstream', index: number): void;
}>();

const routingOptions: { value: RoutingType; label: string }[] = [
  { value: 'proxy', label: 'Reverse Proxy' },
  { value: 'static', label: 'Static Files' },
  { value: 'redirect', label: 'Redirect' },
];

const statusOptions = [301, 302, 307, 308];

const updateDial = (index: number, value: string) => {
  upstreams.value = upstreams.value.map((entry, idx) => (idx === index ? { ...entry, dial: value } : entry));
};

const updateWeight = (index: number, value: number | null | undefined) => {
  upstreams.value = upstreams.value.map((entry, idx) =>
    idx === index ? { ...entry, weight: Number(value) || 1 } : entry
  );
};
</script>

<template>
  <div class="space-y-4">
    <div class="grid grid-cols-3 gap-2">
      <button
        v-for="option in routingOptions"
        :key="option.value"
        type="button"
        class="flex items-center justify-center gap-2 p-2.5 rounded-md border text-xs font-medium transition-colors cursor-pointer"
        :class="
          routingType === option.value
            ? 'border-primary text-primary bg-primary/5 font-semibold'
            : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/40'
        "
        @click="routingType = option.value"
      >
        <span
          class="w-3.5 h-3.5 rounded-full border flex items-center justify-center"
          :class="routingType === option.value ? 'border-primary' : 'border-muted-foreground/60'"
        >
          <span v-if="routingType === option.value" class="w-1.5 h-1.5 rounded-full bg-primary" />
        </span>
        <span>{{ option.label }}</span>
      </button>
    </div>

    <div v-if="routingType === 'proxy'" class="space-y-2">
      <label class="text-xs font-semibold text-foreground flex items-center gap-1">
        <span>Upstream</span>
        <span class="text-threat">*</span>
      </label>

      <div v-for="(entry, idx) in upstreams" :key="entry.id" class="flex items-center gap-2">
        <div class="flex-1 min-w-0">
          <Input
            :model-value="entry.dial"
            placeholder="http://192.168.1.10:8080 — host:port or unix:/path"
            class="h-9 text-xs font-mono"
            @update:model-value="(value) => updateDial(idx, String(value))"
          />
        </div>

        <div v-if="upstreams.length > 1" class="w-24 shrink-0 flex items-center gap-1.5">
          <span class="text-xs text-muted-foreground">Weight</span>
          <NumberInput
            :model-value="entry.weight"
            :min="1"
            :max="100"
            class="h-9 w-14 text-xs font-mono"
            @update:model-value="(value) => updateWeight(idx, value)"
          />
        </div>

        <button
          type="button"
          :disabled="upstreams.length <= 1"
          class="p-2 text-muted-foreground hover:text-threat disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer shrink-0"
          title="Remove upstream"
          @click="emit('remove-upstream', idx)"
        >
          <Trash2 class="w-4 h-4" />
        </button>
      </div>

      <Button
        type="button"
        variant="outline"
        class="w-full h-8 border-dashed border-primary/40 text-primary hover:bg-primary/5 text-xs font-semibold uppercase tracking-wider gap-1.5 shadow-none"
        @click="emit('add-upstream')"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>ADD UPSTREAM</span>
        <Info class="w-3.5 h-3.5 opacity-70 ml-0.5" />
      </Button>

      <div v-if="upstreams.length >= 2" class="space-y-1.5 pt-1">
        <label class="text-xs font-semibold text-foreground">Load Balancing Algorithm</label>
        <Select v-model="loadBalancing">
          <SelectTrigger class="w-full h-9 text-xs">
            <SelectValue placeholder="Select algorithm" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="round_robin">Round-robin (smooth weighted)</SelectItem>
            <SelectItem value="least_conn">Least Connections</SelectItem>
            <SelectItem value="ip_hash">IP Hash (sticky)</SelectItem>
            <SelectItem value="primary_backup">Primary-Backup</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>

    <div v-else-if="routingType === 'static'" class="space-y-1.5">
      <label class="text-xs font-semibold text-foreground flex items-center gap-1">
        <span>Document root</span>
        <span class="text-threat">*</span>
      </label>
      <Input
        v-model="documentRoot"
        placeholder="/srv/www/site"
        class="h-9 text-xs font-mono"
      />
      <p class="text-xs text-muted-foreground leading-relaxed">
        Absolute path on the gateway host. Path traversal is blocked and directory listings stay
        disabled.
      </p>
    </div>

    <div v-else class="grid grid-cols-[1fr_120px] gap-2">
      <div class="space-y-1.5">
        <label class="text-xs font-semibold text-foreground flex items-center gap-1">
          <span>Redirect target</span>
          <span class="text-threat">*</span>
        </label>
        <Input
          v-model="redirectUrl"
          placeholder="https://example.com/landing"
          class="h-9 text-xs font-mono"
        />
      </div>
      <div class="space-y-1.5">
        <label class="text-xs font-semibold text-foreground">Status</label>
        <Select v-model="redirectStatus">
          <SelectTrigger class="w-full h-9 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem v-for="status in statusOptions" :key="status" :value="status">
              {{ status }}
            </SelectItem>
          </SelectContent>
        </Select>
      </div>
      <p class="col-span-2 text-xs text-muted-foreground leading-relaxed">
        Every request for this site is answered with the redirect. Use 308 to preserve the method.
      </p>
    </div>
  </div>
</template>
