<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import { useAuthStore } from '@/stores/auth';
import ConfigDiffViewer from '@/components/ConfigDiffViewer.vue';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Rocket, History, RotateCcw } from 'lucide-vue-next';

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
  <div class="h-full flex flex-col space-y-4 p-6 bg-[#0d0f14] text-zinc-100 rounded-xl border border-zinc-800 shadow-2xl font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-white flex items-center gap-2">
          <Rocket class="w-4 h-4 text-slate-400" />
          <span>Deployments & Rollback History</span>
        </h1>
        <p class="text-[11px] text-zinc-400 mt-0.5">
          Atomic configuration promotion, pre-flight compiler validation, and 1-click snapshot rollback.
        </p>
      </div>

      <div class="flex items-center gap-2">
        <Button
          variant="secondary"
          @click="configStore.refreshDiff()"
        >
          Refresh Diff
        </Button>
        <Button
          v-if="configStore.hasDraftChanges"
          @click="openDeployModal"
          class="gap-1.5 text-white"
        >
          <Rocket class="w-3.5 h-3.5 text-white" />
          <span>Deploy {{ configStore.diffs.length }} Changes</span>
        </Button>
      </div>
    </div>

    <!-- Scrollable content area -->
    <div class="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1">
      <!-- Staged Changes Section -->
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <span>Staged Changes vs. Active Snapshot</span>
            <span
              v-if="configStore.diffs.length > 0"
              class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30"
            >
              {{ configStore.diffs.length }}
            </span>
          </h2>
        </div>

        <ConfigDiffViewer :diffs="configStore.diffs" />
      </div>

      <!-- Deployment History & 1-Click Rollback -->
      <div class="space-y-2 pt-2">
        <div class="flex items-center justify-between">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <History class="w-3.5 h-3.5 text-slate-400" />
            <span>Snapshot Deployment History</span>
          </h2>
        </div>

        <div class="bg-[#1e222a] border border-[#2d3440] rounded-lg overflow-hidden">
          <div v-if="configStore.history.length === 0" class="p-8 text-center text-xs text-slate-400">
            No historical snapshots recorded yet.
          </div>

          <Table v-else>
            <TableHeader class="bg-[#14171d]">
              <TableRow>
                <TableHead class="font-mono text-[11px]">Version</TableHead>
                <TableHead class="font-mono text-[11px]">Description / Commit</TableHead>
                <TableHead class="font-mono text-[11px]">Author</TableHead>
                <TableHead class="font-mono text-[11px]">Applied At</TableHead>
                <TableHead class="font-mono text-[11px] text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow
                v-for="snap in configStore.history"
                :key="snap.version"
                :class="{ 'bg-[#17223B]/20': snap.version === configStore.activeVersion }"
              >
                <TableCell class="font-mono font-bold">
                  <span
                    class="px-2 py-0.5 rounded text-[11px]"
                    :class="snap.version === configStore.activeVersion ? 'bg-[#17223B] text-[#38BDF8] border border-[#2574F5]/30' : 'bg-[#181b20] text-slate-400'"
                  >
                    v{{ snap.version }}
                  </span>
                </TableCell>
                <TableCell class="font-medium text-white">
                  {{ snap.description || 'Routine update' }}
                </TableCell>
                <TableCell class="text-slate-400 font-mono text-[11px]">
                  {{ snap.author || 'system' }}
                </TableCell>
                <TableCell class="text-slate-400 font-mono text-[11px]">
                  {{ new Date(snap.applied_at).toLocaleString() }}
                </TableCell>
                <TableCell class="text-right">
                  <Button
                    v-if="snap.version !== configStore.activeVersion"
                    variant="outline"
                    size="sm"
                    @click="confirmRollback(snap.version)"
                    class="h-7 text-[11px] font-mono text-amber-400 border-amber-500/30 hover:bg-amber-500/10 gap-1"
                  >
                    <RotateCcw class="w-3 h-3 text-slate-400" />
                    <span>1-Click Rollback</span>
                  </Button>
                  <span v-else class="text-[10px] font-mono uppercase text-[#38BDF8] font-semibold">
                    Active
                  </span>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
      </div>
    </div>

    <!-- Deploy Confirmation Modal -->
    <Dialog :open="deployModalOpen" @update:open="deployModalOpen = $event">
      <DialogContent class="max-w-md bg-[#1e222a] border-[#2d3440] p-6 font-sans">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <Rocket class="w-5 h-5 text-slate-400" />
            <DialogTitle>Deploy Staged Configuration</DialogTitle>
          </div>
        </DialogHeader>

        <div class="space-y-4 py-2">
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
              class="w-full px-3 py-2 bg-[#181b20] border border-[#2d3440] rounded-md text-slate-200 text-xs focus:outline-none focus:border-[#2574F5] focus:ring-1 focus:ring-[#2574F5] transition-colors"
            ></textarea>
          </div>
        </div>

        <DialogFooter class="flex justify-end space-x-2 pt-4 border-t border-[#2d3440]">
          <Button
            type="button"
            variant="secondary"
            @click="deployModalOpen = false"
          >
            Cancel
          </Button>
          <Button
            type="button"
            @click="handleDeploy"
            :disabled="deploying"
            class="gap-1.5 text-white"
          >
            <Rocket class="w-3.5 h-3.5 text-white" />
            <span>{{ deploying ? 'Validating & Applying...' : 'Deploy Now' }}</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Rollback Confirmation Modal -->
    <Dialog :open="rollbackModalOpen" @update:open="rollbackModalOpen = $event">
      <DialogContent class="max-w-md bg-[#1e222a] border-[#2d3440] p-6 font-sans">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <RotateCcw class="w-5 h-5 text-slate-400" />
            <DialogTitle>Confirm 1-Click Rollback</DialogTitle>
          </div>
        </DialogHeader>

        <div class="space-y-3 py-2">
          <p class="text-xs text-slate-300">
            Are you sure you want to rollback to configuration snapshot <strong>v{{ selectedRollbackVersion }}</strong>?
          </p>
          <p class="text-xs text-amber-400">
            The active live data plane and all cluster nodes will immediately revert to this historical version.
          </p>
        </div>

        <DialogFooter class="flex justify-end space-x-2 pt-4 border-t border-[#2d3440]">
          <Button
            type="button"
            variant="secondary"
            @click="rollbackModalOpen = false"
          >
            Cancel
          </Button>
          <Button
            type="button"
            @click="handleRollback"
            :disabled="rollingBack"
            class="bg-amber-600 hover:bg-amber-500 text-white gap-1.5"
          >
            <RotateCcw class="w-3.5 h-3.5 text-white" />
            <span>{{ rollingBack ? 'Reverting...' : 'Confirm Rollback' }}</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
