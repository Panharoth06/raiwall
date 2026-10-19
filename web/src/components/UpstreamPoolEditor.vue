<script setup lang="ts">
import { Plus, Trash2, Activity } from 'lucide-vue-next';
import type { Upstream } from '@/api/client';

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
  <div class="space-y-3">
    <div class="flex items-center justify-between">
      <label class="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
        <Activity class="w-3.5 h-3.5 text-emerald-400" />
        <span>Upstream Load Balancing Targets</span>
      </label>
      <button
        type="button"
        @click="addUpstream"
        class="text-xs px-2.5 py-1 bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 rounded hover:bg-emerald-600/30 transition-colors flex items-center space-x-1"
      >
        <Plus class="w-3 h-3" />
        <span>Add Backend</span>
      </button>
    </div>

    <div v-if="modelValue.length === 0" class="p-4 bg-slate-900 border border-slate-800 rounded-lg text-center text-xs text-slate-500">
      No backend upstreams configured. Requests will be handled locally or return 503.
    </div>

    <div v-else class="space-y-2">
      <div
        v-for="(target, idx) in modelValue"
        :key="idx"
        class="p-3 bg-slate-900/90 border border-slate-800 rounded-lg flex flex-wrap items-center gap-3 text-xs"
      >
        <div class="flex-1 min-w-[180px]">
          <span class="block text-[10px] text-slate-500 mb-0.5">Dial Address</span>
          <input
            :value="target.dial"
            @input="updateField(idx, 'dial', ($event.target as HTMLInputElement).value)"
            type="text"
            placeholder="10.0.0.1:8080"
            class="w-full px-2 py-1 bg-slate-800 border border-slate-700 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div class="w-24">
          <span class="block text-[10px] text-slate-500 mb-0.5">Weight ({{ target.weight }})</span>
          <input
            :value="target.weight"
            @input="updateField(idx, 'weight', parseInt(($event.target as HTMLInputElement).value) || 1)"
            type="number"
            min="1"
            max="100"
            class="w-full px-2 py-1 bg-slate-800 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div class="flex-1 min-w-[120px]">
          <span class="block text-[10px] text-slate-500 mb-0.5">Health Check Path</span>
          <input
            :value="target.health_check_path || ''"
            @input="updateField(idx, 'health_check_path', ($event.target as HTMLInputElement).value)"
            type="text"
            placeholder="/healthz"
            class="w-full px-2 py-1 bg-slate-800 border border-slate-700 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div class="w-20">
          <span class="block text-[10px] text-slate-500 mb-0.5">Interval</span>
          <input
            :value="target.interval || '10s'"
            @input="updateField(idx, 'interval', ($event.target as HTMLInputElement).value)"
            type="text"
            placeholder="10s"
            class="w-full px-2 py-1 bg-slate-800 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <button
          type="button"
          @click="removeUpstream(idx)"
          class="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors self-end mb-0.5"
          title="Remove target"
        >
          <Trash2 class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  </div>
</template>
