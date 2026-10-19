<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api, type ApiKeyItem } from '@/api/client';
import { Key, Plus, Trash2, Copy, Check, X, Shield } from 'lucide-vue-next';

const keys = ref<ApiKeyItem[]>([]);
const loading = ref(false);

const modalOpen = ref(false);
const newKeyName = ref('');
const newKeyRole = ref<'admin' | 'viewer'>('viewer');
const newKeyExpires = ref(30);

const generatedToken = ref<string | null>(null);
const copied = ref(false);

const loadKeys = async () => {
  loading.value = true;
  try {
    keys.value = await api.listApiKeys();
  } catch {
    // ignore
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadKeys();
});

const handleCreateKey = async () => {
  if (!newKeyName.value) return;
  try {
    const res = await api.createApiKey({
      name: newKeyName.value,
      role: newKeyRole.value,
      expires_in_days: newKeyExpires.value,
    });
    generatedToken.value = res.token;
    await loadKeys();
  } catch (err: unknown) {
    alert(err instanceof Error ? err.message : 'Failed to create API key');
  }
};

const copyToken = () => {
  if (generatedToken.value) {
    navigator.clipboard.writeText(generatedToken.value);
    copied.value = true;
    setTimeout(() => {
      copied.value = false;
    }, 2000);
  }
};

const handleDeleteKey = async (id: string) => {
  if (confirm('Revoke this API key? Applications using it will lose access immediately.')) {
    await api.deleteApiKey(id);
    await loadKeys();
  }
};
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-sm font-semibold text-white flex items-center space-x-2">
          <Key class="w-4 h-4 text-emerald-400" />
          <span>Management API & MCP Bearer Keys</span>
        </h3>
        <p class="text-xs text-slate-400 mt-0.5">
          Authenticate automated CI/CD pipelines, MCP desktop agents, and external scripts.
        </p>
      </div>

      <button
        @click="modalOpen = true; generatedToken = null;"
        class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>Generate API Key</span>
      </button>
    </div>

    <!-- Keys Table -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      <div v-if="keys.length === 0" class="p-8 text-center text-xs text-slate-500">
        No active API keys found. Generate a key to access the Huma REST API or MCP server.
      </div>

      <table v-else class="w-full text-left text-xs text-slate-300">
        <thead class="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
          <tr>
            <th class="py-2.5 px-4">Key Name</th>
            <th class="py-2.5 px-4">Prefix</th>
            <th class="py-2.5 px-4">Role</th>
            <th class="py-2.5 px-4">Created</th>
            <th class="py-2.5 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/60">
          <tr v-for="key in keys" :key="key.id" class="hover:bg-slate-800/40">
            <td class="py-3 px-4 font-medium text-white">{{ key.name }}</td>
            <td class="py-3 px-4 font-mono text-emerald-400">{{ key.prefix }}...</td>
            <td class="py-3 px-4">
              <span
                class="px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider"
                :class="key.role === 'admin' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-400'"
              >
                {{ key.role }}
              </span>
            </td>
            <td class="py-3 px-4 text-slate-400">{{ new Date(key.created_at).toLocaleDateString() }}</td>
            <td class="py-3 px-4 text-right">
              <button
                @click="handleDeleteKey(key.id)"
                class="p-1 text-slate-400 hover:text-rose-400 rounded transition-colors"
                title="Revoke key"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Generate Key Modal -->
    <div v-if="modalOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col">
        <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <Key class="w-5 h-5 text-emerald-400" />
            <h2 class="text-base font-semibold text-white">Generate API Bearer Token</h2>
          </div>
          <button @click="modalOpen = false" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
            <X class="w-4 h-4" />
          </button>
        </div>

        <div class="p-6 space-y-4">
          <div v-if="!generatedToken">
            <div class="space-y-3">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Key Name</label>
                <input
                  v-model="newKeyName"
                  type="text"
                  placeholder="e.g. CI/CD Deployer or Claude Desktop"
                  class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">RBAC Role</label>
                <select
                  v-model="newKeyRole"
                  class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
                >
                  <option value="viewer">Viewer (Read-only status & metrics)</option>
                  <option value="admin">Admin (Read/Write mutating operations)</option>
                </select>
              </div>

              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Expiration (Days)</label>
                <input
                  v-model.number="newKeyExpires"
                  type="number"
                  min="1"
                  max="365"
                  class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div class="mt-6 flex justify-end space-x-3">
              <button
                type="button"
                @click="modalOpen = false"
                class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                @click="handleCreateKey"
                class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium"
              >
                Generate Token
              </button>
            </div>
          </div>

          <div v-else class="space-y-4">
            <div class="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-300">
              <strong>Make sure to copy your API key now.</strong> You won't be able to see it again!
            </div>

            <div class="relative">
              <input
                type="text"
                readonly
                :value="generatedToken"
                class="w-full px-3 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-emerald-400 font-mono text-xs pr-10 focus:outline-none"
              />
              <button
                @click="copyToken"
                class="absolute right-2 top-2 p-1 text-slate-400 hover:text-emerald-400 rounded"
                title="Copy to clipboard"
              >
                <component :is="copied ? Check : Copy" class="w-4 h-4" />
              </button>
            </div>

            <div class="flex justify-end pt-2">
              <button
                type="button"
                @click="modalOpen = false"
                class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
