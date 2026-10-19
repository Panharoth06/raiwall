<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { ExceptionRule } from '@/api/client';
import ExceptionTestModal from '@/components/ExceptionTestModal.vue';
import { Plus, Shield, Trash2, Play, Sparkles, X, Save } from 'lucide-vue-next';

const configStore = useConfigStore();

const showAddModal = ref(false);
const testModalOpen = ref(false);
const selectedRuleForTest = ref<ExceptionRule | null>(null);

const newHost = ref('');
const newPath = ref('');
const newMethod = ref('ALL');
const newLocation = ref('query');
const newParamName = ref('');
const newReason = ref('');
const newRuleId = ref('ALL');

const openAddModal = () => {
  newHost.value = '';
  newPath.value = '';
  newMethod.value = 'ALL';
  newLocation.value = 'query';
  newParamName.value = '';
  newReason.value = '';
  newRuleId.value = 'ALL';
  showAddModal.value = true;
};

const handleSaveException = async () => {
  if (!newPath.value || !newParamName.value) {
    alert('Path and Parameter Name are required');
    return;
  }

  await configStore.createException({
    host: newHost.value || '*',
    path: newPath.value,
    method: newMethod.value,
    location: newLocation.value,
    param_name: newParamName.value,
    reason: newReason.value || 'False-positive suppression',
    rule_id: newRuleId.value || 'ALL',
  });

  showAddModal.value = false;
};

const openTestSimulator = (rule: ExceptionRule) => {
  selectedRuleForTest.value = rule;
  testModalOpen.value = true;
};

const handleDelete = async (id: string) => {
  if (confirm('Delete this exception rule?')) {
    await configStore.deleteException(id);
  }
};
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight flex items-center space-x-2.5">
          <Shield class="w-6 h-6 text-emerald-400" />
          <span>False-Positive Exception Rules</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">
          Granular parameter-level bypasses: Host + Path + Method + Location + Param Name to prevent legitimate transaction drops.
        </p>
      </div>

      <button
        @click="openAddModal"
        class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-2"
      >
        <Plus class="w-4 h-4" />
        <span>Add Exception Rule</span>
      </button>
    </div>

    <!-- Exceptions Table -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      <div v-if="configStore.exceptions.length === 0" class="p-12 text-center">
        <Sparkles class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 class="text-sm font-semibold text-slate-300">No exception rules defined</h3>
        <p class="text-xs text-slate-500 mt-1 mb-4">
          Suppress false-positives without disabling the WAF globally.
        </p>
        <button
          @click="openAddModal"
          class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors"
        >
          Add First Exception
        </button>
      </div>

      <table v-else class="w-full text-left text-xs text-slate-300">
        <thead class="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
          <tr>
            <th class="py-3 px-4">Host / Path</th>
            <th class="py-3 px-4">Method</th>
            <th class="py-3 px-4">Location</th>
            <th class="py-3 px-4">Parameter Name</th>
            <th class="py-3 px-4">Suppressed Threat</th>
            <th class="py-3 px-4">Reason</th>
            <th class="py-3 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/60">
          <tr v-for="rule in configStore.exceptions" :key="rule.id" class="hover:bg-slate-800/40 transition-colors">
            <td class="py-3.5 px-4">
              <span class="text-white font-medium block">{{ rule.path }}</span>
              <span class="text-[11px] text-slate-500 font-mono">{{ rule.host || '*' }}</span>
            </td>
            <td class="py-3.5 px-4 font-mono text-[11px]">
              <span class="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300">
                {{ rule.method }}
              </span>
            </td>
            <td class="py-3.5 px-4">
              <span class="capitalize text-slate-300 font-medium">{{ rule.location }}</span>
            </td>
            <td class="py-3.5 px-4 font-mono text-emerald-400 font-semibold">
              {{ rule.param_name }}
            </td>
            <td class="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
              {{ rule.rule_id || 'ALL' }}
            </td>
            <td class="py-3.5 px-4 text-slate-400 truncate max-w-xs">
              {{ rule.reason }}
            </td>
            <td class="py-3.5 px-4 text-right space-x-2">
              <button
                @click="openTestSimulator(rule)"
                class="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors"
                title="Test with simulator"
              >
                <Play class="w-4 h-4" />
              </button>
              <button
                @click="handleDelete(rule.id)"
                class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                title="Delete exception"
              >
                <Trash2 class="w-4 h-4" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Add Exception Modal -->
    <div v-if="showAddModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div class="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col">
        <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div class="flex items-center space-x-2.5">
            <Shield class="w-5 h-5 text-emerald-400" />
            <h2 class="text-base font-semibold text-white">New Parameter Exception Rule</h2>
          </div>
          <button @click="showAddModal = false" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
            <X class="w-4 h-4" />
          </button>
        </div>

        <div class="p-6 space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Host (Optional)</label>
              <input
                v-model="newHost"
                type="text"
                placeholder="* or api.example.com"
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Path</label>
              <input
                v-model="newPath"
                type="text"
                placeholder="/api/v1/search"
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">HTTP Method</label>
              <select
                v-model="newMethod"
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
              >
                <option value="ALL">ALL</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Parameter Location</label>
              <select
                v-model="newLocation"
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
              >
                <option value="query">Query Parameter</option>
                <option value="header">Request Header</option>
                <option value="cookie">Cookie</option>
                <option value="body">Request Body</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Parameter Name</label>
              <input
                v-model="newParamName"
                type="text"
                placeholder="e.g. search_term"
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Rule ID (or ALL)</label>
              <input
                v-model="newRuleId"
                type="text"
                placeholder="ALL or SQLI_*"
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Reason / Context</label>
            <input
              v-model="newReason"
              type="text"
              placeholder="e.g. Valid SQL editor payload in internal tool"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div class="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3">
          <button
            type="button"
            @click="showAddModal = false"
            class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            @click="handleSaveException"
            class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5"
          >
            <Save class="w-3.5 h-3.5" />
            <span>Add to Draft</span>
          </button>
        </div>
      </div>
    </div>

    <!-- Test Simulator Modal -->
    <ExceptionTestModal
      :open="testModalOpen"
      :rule="selectedRuleForTest"
      @close="testModalOpen = false"
    />
  </div>
</template>
