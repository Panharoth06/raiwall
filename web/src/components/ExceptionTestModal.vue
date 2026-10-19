<script setup lang="ts">
import { ref, watch } from 'vue';
import { api, type ExceptionRule } from '@/api/client';
import { X, Play, ShieldAlert, ShieldCheck } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  rule?: ExceptionRule | null;
}>();

defineEmits<{
  (e: 'close'): void;
}>();

const testHost = ref('api.example.com');
const testPath = ref('/v1/search');
const testMethod = ref('GET');
const testParamName = ref('query');
const testParamVal = ref("' OR 1=1 --");

const testing = ref(false);
const result = ref<{ matched: boolean; reason: string } | null>(null);

watch(
  () => props.rule,
  (val) => {
    if (val) {
      testHost.value = val.host || 'api.example.com';
      testPath.value = val.path || '/v1/search';
      testMethod.value = val.method || 'GET';
      testParamName.value = val.param_name || 'query';
    }
    result.value = null;
  },
  { immediate: true }
);

const runSimulation = async () => {
  testing.value = true;
  result.value = null;
  try {
    const res = await api.dryRunException({
      rule: props.rule || {
        host: testHost.value,
        path: testPath.value,
        method: testMethod.value,
        location: 'query',
        param_name: testParamName.value,
        rule_id: 'ALL',
      },
      request: {
        host: testHost.value,
        path: testPath.value,
        method: testMethod.value,
        params: { [testParamName.value]: testParamVal.value },
      },
    });
    result.value = res;
  } catch (err: unknown) {
    result.value = {
      matched: false,
      reason: err instanceof Error ? err.message : 'Simulation failed',
    };
  } finally {
    testing.value = false;
  }
};
</script>

<template>
  <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
    <div class="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div class="flex items-center space-x-2.5">
          <Play class="w-5 h-5 text-emerald-400" />
          <h2 class="text-base font-semibold text-white">Exception Rule Test Simulator</h2>
        </div>
        <button @click="$emit('close')" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Body -->
      <div class="p-6 space-y-4">
        <p class="text-xs text-slate-400">
          Test synthetic HTTP parameters against this exception rule to confirm false-positive suppression before deployment.
        </p>

        <div class="grid grid-cols-3 gap-3">
          <div>
            <label class="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">Method</label>
            <select
              v-model="testMethod"
              class="w-full px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          <div class="col-span-2">
            <label class="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">Host</label>
            <input
              v-model="testHost"
              type="text"
              class="w-full px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div>
          <label class="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">Path</label>
          <input
            v-model="testPath"
            type="text"
            class="w-full px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">Parameter Name</label>
            <input
              v-model="testParamName"
              type="text"
              class="w-full px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label class="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">Parameter Value (Synthetic Payload)</label>
            <input
              v-model="testParamVal"
              type="text"
              class="w-full px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs font-mono focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <!-- Simulation Result -->
        <div v-if="result" class="p-4 rounded-lg border text-xs" :class="result.matched ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'">
          <div class="flex items-center space-x-2 font-semibold">
            <component :is="result.matched ? ShieldCheck : ShieldAlert" class="w-5 h-5 flex-shrink-0" />
            <span>{{ result.matched ? 'MATCHED — False-positive successfully bypassed' : 'NOT MATCHED — Request will be inspected by WAF' }}</span>
          </div>
          <p class="text-[11px] text-slate-400 mt-1 pl-7">{{ result.reason }}</p>
        </div>
      </div>

      <!-- Footer -->
      <div class="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3">
        <button
          type="button"
          @click="$emit('close')"
          class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
        >
          Close
        </button>
        <button
          type="button"
          @click="runSimulation"
          :disabled="testing"
          class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5"
        >
          <Play class="w-3.5 h-3.5" />
          <span>{{ testing ? 'Simulating...' : 'Run Simulation' }}</span>
        </button>
      </div>
    </div>
  </div>
</template>
