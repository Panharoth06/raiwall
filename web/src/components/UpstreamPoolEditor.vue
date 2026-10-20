<script setup lang="ts">
import { Plus, Trash2, Activity } from 'lucide-vue-next';
import type { Upstream } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const props = defineProps<{
  modelValue: Upstream[];
}>();

const emit = defineEmits<{
  (e: 'update:modelValue', value: Upstream[]): void;
}>();

const addUpstream = () => {
  const updated = [
    ...props.modelValue,
    {
      dial: '127.0.0.1:8080',
      weight: 1,
      health_check_path: '/healthz',
      interval: '10s',
      fail_timeout: '30s',
    },
  ];
  emit('update:modelValue', updated);
};

const removeUpstream = (index: number) => {
  const updated = props.modelValue.filter((_, i) => i !== index);
  emit('update:modelValue', updated);
};

const updateField = (index: number, field: keyof Upstream, val: any) => {
  const updated = props.modelValue.map((item, i) => {
    if (i === index) {
      return { ...item, [field]: val };
    }
    return item;
  });
  emit('update:modelValue', updated);
};
</script>

<template>
  <div class="space-y-3 font-sans">
    <div class="flex items-center justify-between">
      <label class="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
        <Activity class="w-3.5 h-3.5 text-slate-400" />
        <span>Upstream Load Balancing Targets</span>
      </label>
      <Button
        type="button"
        size="sm"
        variant="secondary"
        @click="addUpstream"
        class="gap-1 text-xs"
      >
        <Plus class="w-3 h-3" />
        <span>Add Backend</span>
      </Button>
    </div>

    <div v-if="modelValue.length === 0" class="p-4 bg-[#181b20] border border-[#2d3440] rounded-lg text-center text-xs text-slate-500">
      No backend upstreams configured. Requests will be handled locally or return 503.
    </div>

    <div v-else class="space-y-2">
      <div
        v-for="(target, idx) in modelValue"
        :key="idx"
        class="p-3 bg-[#181b20] border border-[#2d3440] rounded-lg flex flex-wrap items-center gap-3 text-xs"
      >
        <div class="flex-1 min-w-[180px]">
          <span class="block text-[10px] text-slate-400 mb-0.5">Dial Address</span>
          <Input
            :model-value="target.dial"
            @update:model-value="updateField(idx, 'dial', String($event))"
            placeholder="10.0.0.1:8080"
          />
        </div>

        <div class="w-24">
          <span class="block text-[10px] text-slate-400 mb-0.5">Weight ({{ target.weight }})</span>
          <Input
            :model-value="target.weight"
            @update:model-value="updateField(idx, 'weight', parseInt(String($event)) || 1)"
            type="number"
            min="1"
            max="100"
          />
        </div>

        <div class="flex-1 min-w-[120px]">
          <span class="block text-[10px] text-slate-400 mb-0.5">Health Check Path</span>
          <Input
            :model-value="target.health_check_path || ''"
            @update:model-value="updateField(idx, 'health_check_path', String($event))"
            placeholder="/healthz"
          />
        </div>

        <div class="w-20">
          <span class="block text-[10px] text-slate-400 mb-0.5">Interval</span>
          <Input
            :model-value="target.interval || '10s'"
            @update:model-value="updateField(idx, 'interval', String($event))"
            placeholder="10s"
          />
        </div>

        <Button
          type="button"
          variant="ghost"
          size="icon"
          @click="removeUpstream(idx)"
          class="h-8 w-8 text-slate-400 hover:text-red-400 self-end mb-0.5"
          title="Remove target"
        >
          <Trash2 class="w-3.5 h-3.5" />
        </Button>
      </div>
    </div>
  </div>
</template>
