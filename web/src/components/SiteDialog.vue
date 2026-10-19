<script setup lang="ts">
import { ref, watch } from 'vue';
import type { Site, Upstream } from '@/api/client';
import UpstreamPoolEditor from './UpstreamPoolEditor.vue';
import { X, Globe, Save } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  site?: Site | null;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', site: Partial<Site>): void;
}>();

const formName = ref('');
const formHostnames = ref('');
const formMode = ref<'defense' | 'audit' | 'offline'>('defense');
const formUpstreams = ref<Upstream[]>([]);
const formBlockCode = ref(403);
const formOfflineCode = ref(503);

watch(
  () => props.site,
  (val) => {
    if (val) {
      formName.value = val.name || '';
      formHostnames.value = (val.hostnames || []).join(', ');
      formMode.value = val.mode || 'defense';
      formUpstreams.value = JSON.parse(JSON.stringify(val.upstreams || []));
      formBlockCode.value = val.block_status_code || 403;
      formOfflineCode.value = val.offline_status_code || 503;
    } else {
      formName.value = '';
      formHostnames.value = '';
      formMode.value = 'defense';
      formUpstreams.value = [];
      formBlockCode.value = 403;
      formOfflineCode.value = 503;
    }
  },
  { immediate: true }
);

const handleSave = () => {
  const hosts = formHostnames.value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  emit('save', {
    id: props.site?.id,
    name: formName.value,
    hostnames: hosts,
    mode: formMode.value,
    upstreams: formUpstreams.value,
    block_status_code: formBlockCode.value,
    offline_status_code: formOfflineCode.value,
  });
  emit('close');
};
</script>

<template>
  <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
    <div class="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col max-h-[90vh]">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between flex-shrink-0">
        <div class="flex items-center space-x-2.5">
          <Globe class="w-5 h-5 text-emerald-400" />
          <h2 class="text-base font-semibold text-white">
            {{ site ? 'Edit Protected Site' : 'Add Protected Site' }}
          </h2>
        </div>
        <button @click="$emit('close')" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Body -->
      <div class="p-6 overflow-y-auto space-y-4 flex-1">
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Site Name</label>
            <input
              v-model="formName"
              type="text"
              placeholder="e.g. Payment Gateway"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Operational Mode</label>
            <select
              v-model="formMode"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            >
              <option value="defense">Defense (Active Threat Blocking)</option>
              <option value="audit">Audit (Log & Alert Only)</option>
              <option value="offline">Offline (Maintenance 503)</option>
            </select>
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            Hostnames (comma separated)
          </label>
          <input
            v-model="formHostnames"
            type="text"
            placeholder="api.example.com, pay.example.com"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Block HTTP Status</label>
            <input
              v-model.number="formBlockCode"
              type="number"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Offline HTTP Status</label>
            <input
              v-model.number="formOfflineCode"
              type="number"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div class="pt-2 border-t border-slate-800">
          <UpstreamPoolEditor v-model="formUpstreams" />
        </div>
      </div>

      <!-- Footer -->
      <div class="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3 flex-shrink-0">
        <button
          type="button"
          @click="$emit('close')"
          class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          @click="handleSave"
          class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5"
        >
          <Save class="w-3.5 h-3.5" />
          <span>Save to Draft</span>
        </button>
      </div>
    </div>
  </div>
</template>
