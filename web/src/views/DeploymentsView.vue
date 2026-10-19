<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import { useAuthStore } from '@/stores/auth';
import ConfigDiffViewer from '@/components/ConfigDiffViewer.vue';
import { Rocket, History, RotateCcw, CheckCircle, AlertTriangle, X } from 'lucide-vue-next';

const configStore = useConfigStore();
const authStore = useAuthStore();

const deployModalOpen = ref(false);
const commitDescription = ref('');
const deploying = ref(false);
const deployError = ref<string | null>(null);

const rollbackModalOpen = ref(false);
const selectedRollbackVersion = ref<number | null>(null);
const rollingBack = ref(false);

const openDeployModal = () => {
  commitDescription.value = '';
  deployError.value = null;
  deployModalOpen.value = true;
};

const handleDeploy = async () => {
  deploying.value = true;
  deployError.value = null;
  try {
    const author = authStore.user?.username || 'admin';
    const desc = commitDescription.value || 'Staged configuration deployment';
    await configStore.applyDraft(author, desc);
    deployModalOpen.value = false;
  } catch (err: unknown) {
    deployError.value = err instanceof Error ? err.message : 'Pre-flight validation failed';
  } finally {
    deploying.value = false;
  }
};

const confirmRollback = (version: number) => {
  selectedRollbackVersion.value = version;
  rollbackModalOpen.value = true;
};

const handleRollback = async () => {
  if (selectedRollbackVersion.value === null) return;
  rollingBack.value = true;
  try {
    await configStore.rollbackTo(selectedRollbackVersion.value);
    rollbackModalOpen.value = false;
  } catch (err: unknown) {
    alert(err instanceof Error ? err.message : 'Rollback failed');
  } finally {
    rollingBack.value = false;
  }
};
</script>

<template>
  <div class="space-y-8 max-w-5xl">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight flex items-center space-x-2.5">
          <Rocket class="w-6 h-6 text-emerald-400" />
          <span>Staged Deployments & Snapshot Rollback</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">
          Review staged draft changes against active snapshot with pre-flight AST compiler validation before atomic swap.
        </p>
      </div>

      <button
        v-if="configStore.hasDraftChanges"
        @click="openDeployModal"
        class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition-all flex items-center space-x-2 shadow-lg shadow-emerald-950 animate-pulse"
      >
        <Rocket class="w-4 h-4" />
        <span>Deploy {{ configStore.diffs.length }} Changes</span>
      </button>
    </div>

    <!-- Active Live Snapshot Banner -->
    <div class="bg-gradient-to-r from-slate-900 to-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl flex items-center justify-between">
      <div class="flex items-center space-x-4">
        <div class="h-12 w-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
          <CheckCircle class="w-6 h-6" />
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <span class="text-base font-bold text-white">Active Production Snapshot</span>
            <span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/20 text-emerald-400">
              v{{ configStore.activeVersion }}
            </span>
          </div>
          <p class="text-xs text-slate-400 mt-1">
            Running lock-free in memory via <code>atomic.Pointer[ConfigSnapshot]</code> with zero dropped requests.
          </p>
        </div>
      </div>

      <button
        @click="configStore.refreshDiff()"
        class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
      >
        Refresh Status
      </button>
    </div>

    <!-- Staged Changes Section -->
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold text-white flex items-center space-x-2">
          <span>Staged Changes vs. Active Snapshot</span>
          <span
            v-if="configStore.diffs.length > 0"
            class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400"
          >
            {{ configStore.diffs.length }}
          </span>
        </h2>
      </div>

      <ConfigDiffViewer :diffs="configStore.diffs" />
    </div>

    <!-- Deployment History & 1-Click Rollback -->
    <div class="space-y-4 pt-4">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold text-white flex items-center space-x-2">
          <History class="w-4 h-4 text-emerald-400" />
          <span>Snapshot Deployment History</span>
        </h2>
      </div>

      <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div v-if="configStore.history.length === 0" class="p-8 text-center text-xs text-slate-500">
          No historical snapshots recorded yet.
        </div>

        <table v-else class="w-full text-left text-xs text-slate-300">
          <thead class="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
            <tr>
              <th class="py-3 px-4">Version</th>
              <th class="py-3 px-4">Description / Commit</th>
              <th class="py-3 px-4">Author</th>
              <th class="py-3 px-4">Applied At</th>
              <th class="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800/60">
            <tr
              v-for="snap in configStore.history"
              :key="snap.version"
              class="hover:bg-slate-800/40 transition-colors"
              :class="{ 'bg-emerald-500/5': snap.version === configStore.activeVersion }"
            >
              <td class="py-3.5 px-4 font-mono font-bold">
                <span
                  class="px-2 py-0.5 rounded"
                  :class="snap.version === configStore.activeVersion ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-300'"
                >
                  v{{ snap.version }}
                </span>
              </td>
              <td class="py-3.5 px-4 font-medium text-white">
                {{ snap.description || 'Routine update' }}
              </td>
              <td class="py-3.5 px-4 text-slate-400">
                {{ snap.author || 'system' }}
              </td>
              <td class="py-3.5 px-4 text-slate-400">
                {{ new Date(snap.applied_at).toLocaleString() }}
              </td>
              <td class="py-3.5 px-4 text-right">
                <button
                  v-if="snap.version !== configStore.activeVersion"
                  @click="confirmRollback(snap.version)"
                  class="px-2.5 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded text-[11px] font-medium transition-colors flex items-center space-x-1 ml-auto"
                >
                  <RotateCcw class="w-3 h-3" />
                  <span>1-Click Rollback</span>
                </button>
                <span v-else class="text-[11px] text-emerald-400 font-semibold uppercase tracking-wider">
                  Active
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Deploy Confirmation Modal -->
    <div v-if="deployModalOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col">
        <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <Rocket class="w-5 h-5 text-emerald-400" />
            <h2 class="text-base font-semibold text-white">Deploy Staged Configuration</h2>
          </div>
          <button @click="deployModalOpen = false" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
            <X class="w-4 h-4" />
          </button>
        </div>

        <div class="p-6 space-y-4">
          <p class="text-xs text-slate-400">
            This will run pre-flight AST compiler validation, generate a new immutable snapshot, and atomically hot-swap the live pointer across all cluster nodes.
          </p>

          <div v-if="deployError" class="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs">
            {{ deployError }}
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Deployment Description</label>
            <textarea
              v-model="commitDescription"
              rows="2"
              placeholder="e.g. Added exception rule for payment search query"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            ></textarea>
          </div>
        </div>

        <div class="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3">
          <button
            type="button"
            @click="deployModalOpen = false"
            class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
          >
            Cancel
          </button>
          <button
            type="button"
            @click="handleDeploy"
            :disabled="deploying"
            class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium flex items-center space-x-1.5"
          >
            <Rocket class="w-3.5 h-3.5" />
            <span>{{ deploying ? 'Validating & Applying...' : 'Deploy Now' }}</span>
          </button>
        </div>
      </div>
    </div>

    <!-- Rollback Confirmation Modal -->
    <div v-if="rollbackModalOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col">
        <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <RotateCcw class="w-5 h-5 text-amber-400" />
            <h2 class="text-base font-semibold text-white">Confirm 1-Click Rollback</h2>
          </div>
          <button @click="rollbackModalOpen = false" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
            <X class="w-4 h-4" />
          </button>
        </div>

        <div class="p-6 space-y-3">
          <p class="text-xs text-slate-300">
            Are you sure you want to rollback to configuration snapshot <strong>v{{ selectedRollbackVersion }}</strong>?
          </p>
          <p class="text-xs text-amber-400">
            The active live data plane and all cluster nodes will immediately revert to this historical version.
          </p>
        </div>

        <div class="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3">
          <button
            type="button"
            @click="rollbackModalOpen = false"
            class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
          >
            Cancel
          </button>
          <button
            type="button"
            @click="handleRollback"
            :disabled="rollingBack"
            class="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-medium flex items-center space-x-1.5"
          >
            <RotateCcw class="w-3.5 h-3.5" />
            <span>{{ rollingBack ? 'Reverting...' : 'Confirm Rollback' }}</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
