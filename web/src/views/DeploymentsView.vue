<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useConfigStore } from '@/stores/config'
import ConfigDiffViewer from '@/components/ConfigDiffViewer.vue'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Rocket, RotateCcw, History } from 'lucide-vue-next'

const configStore = useConfigStore()

const deployModalOpen = ref(false)
const commitDescription = ref('')
const deploying = ref(false)
const deployError = ref<string | null>(null)

const rollbackModalOpen = ref(false)
const selectedRollbackVersion = ref<number | null>(null)
const rollingBack = ref(false)
const rollbackError = ref<string | null>(null)

onMounted(async () => {
  await configStore.loadAll()
})

const openDeployModal = () => {
  commitDescription.value = ''
  deployError.value = null
  deployModalOpen.value = true
}

const handleDeploy = async () => {
  deploying.value = true
  deployError.value = null
  try {
    await configStore.applyDraft(commitDescription.value || 'Deployed from web console')
    deployModalOpen.value = false
  } catch (err: unknown) {
    deployError.value = err instanceof Error ? err.message : 'Deployment failed'
  } finally {
    deploying.value = false
  }
}

const confirmRollback = (version: number) => {
  selectedRollbackVersion.value = version
  rollbackError.value = null
  rollbackModalOpen.value = true
}

const handleRollback = async () => {
  if (selectedRollbackVersion.value === null) return
  rollingBack.value = true
  rollbackError.value = null
  try {
    await configStore.rollbackTo(selectedRollbackVersion.value)
    rollbackModalOpen.value = false
  } catch (err: unknown) {
    rollbackError.value = err instanceof Error ? err.message : 'Rollback failed'
  } finally {
    rollingBack.value = false
  }
}
</script>

<template>
  <div class="h-full flex flex-col space-y-6 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-border shrink-0">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <Rocket class="w-5 h-5 text-primary" />
          <span>Deployments & Rollback History</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Atomic configuration promotion, pre-flight compiler validation, and 1-click snapshot rollback.
        </p>
      </div>

      <div class="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          @click="configStore.refreshDiff()"
        >
          Refresh Diff
        </Button>
        <Button
          v-if="configStore.hasDraftChanges"
          size="sm"
          @click="openDeployModal"
          class="gap-1.5"
        >
          <Rocket class="w-4 h-4" />
          <span>Deploy {{ configStore.diffs.length }} Changes</span>
        </Button>
      </div>
    </div>

    <!-- Scrollable content area -->
    <div class="flex-1 min-h-0 overflow-y-auto space-y-6 pr-1">
      <!-- Staged Changes Section -->
      <div class="space-y-3">
        <div class="flex items-center justify-between">
          <h2 class="text-base font-semibold text-foreground flex items-center gap-2">
            <span>Staged Changes vs. Active Snapshot</span>
            <span
              v-if="configStore.diffs.length > 0"
              class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-warning/20 text-warning border border-warning/30"
            >
              {{ configStore.diffs.length }}
            </span>
          </h2>
        </div>

        <ConfigDiffViewer :diffs="configStore.diffs" />
      </div>

      <!-- Deployment History & 1-Click Rollback -->
      <div class="space-y-3 pt-2">
        <div class="flex items-center justify-between">
          <h2 class="text-base font-semibold text-foreground flex items-center gap-2">
            <History class="w-4 h-4 text-muted-foreground" />
            <span>Snapshot Deployment History</span>
          </h2>
        </div>

        <div class="bg-card border border-border rounded-lg overflow-hidden">
          <EmptyState
            v-if="configStore.history.length === 0"
            :icon="History"
            title="No historical snapshots recorded yet"
            description="Configuration snapshots will appear here as updates are committed and deployed."
            class="py-8"
          />

          <Table v-else>
            <TableHeader>
              <TableRow>
                <TableHead class="text-xs uppercase font-semibold">Version</TableHead>
                <TableHead class="text-xs uppercase font-semibold">Description / Commit</TableHead>
                <TableHead class="text-xs uppercase font-semibold">Author</TableHead>
                <TableHead class="text-xs uppercase font-semibold">Applied At</TableHead>
                <TableHead class="text-right text-xs uppercase font-semibold">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow
                v-for="snap in configStore.history"
                :key="snap.version"
                :class="{ 'bg-primary/5': snap.version === configStore.activeVersion }"
              >
                <TableCell class="font-mono font-bold">
                  <span
                    class="px-2 py-0.5 rounded text-xs font-mono"
                    :class="snap.version === configStore.activeVersion ? 'bg-primary/10 text-primary border border-primary/30' : 'bg-muted text-muted-foreground'"
                  >
                    v{{ snap.version }}
                  </span>
                </TableCell>
                <TableCell class="font-medium text-foreground text-sm">
                  {{ snap.description || 'Routine update' }}
                </TableCell>
                <TableCell class="text-muted-foreground font-mono text-xs">
                  {{ snap.author || 'system' }}
                </TableCell>
                <TableCell class="text-muted-foreground font-mono text-xs">
                  {{ new Date(snap.applied_at).toLocaleString() }}
                </TableCell>
                <TableCell class="text-right">
                  <Button
                    v-if="snap.version !== configStore.activeVersion"
                    variant="outline"
                    size="sm"
                    @click="confirmRollback(snap.version)"
                    class="h-7 text-xs font-mono text-warning border-warning/30 hover:bg-warning/10 gap-1"
                  >
                    <RotateCcw class="w-3.5 h-3.5 text-warning" />
                    <span>1-Click Rollback</span>
                  </Button>
                  <span v-else class="text-xs font-mono uppercase text-primary font-semibold">
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
      <DialogContent class="max-w-md bg-card border-border">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <Rocket class="w-5 h-5 text-primary" />
            <DialogTitle class="text-base font-semibold text-foreground">Deploy Staged Configuration</DialogTitle>
          </div>
        </DialogHeader>

        <div class="space-y-4 py-2">
          <p class="text-sm text-muted-foreground">
            This will run pre-flight AST compiler validation, generate a new immutable snapshot, and atomically hot-swap the live pointer across all cluster nodes.
          </p>

          <div v-if="deployError" class="p-3 bg-threat/10 border border-threat/30 rounded-lg text-threat text-xs">
            {{ deployError }}
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Deployment Description</label>
            <textarea
              v-model="commitDescription"
              rows="2"
              placeholder="e.g. Added exception rule for payment search query"
              class="w-full px-3 py-2 bg-card border border-input rounded-md text-foreground placeholder:text-muted-foreground text-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring transition-colors"
            ></textarea>
          </div>
        </div>

        <DialogFooter class="flex gap-2 justify-end pt-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            @click="deployModalOpen = false"
          >
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            @click="handleDeploy"
            :disabled="deploying"
            class="gap-1.5"
          >
            <Rocket class="w-4 h-4" />
            <span>{{ deploying ? 'Validating & Applying...' : 'Deploy Now' }}</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Rollback Confirmation Modal -->
    <Dialog :open="rollbackModalOpen" @update:open="rollbackModalOpen = $event">
      <DialogContent class="max-w-md bg-card border-border">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <RotateCcw class="w-5 h-5 text-warning" />
            <DialogTitle class="text-base font-semibold text-foreground">Confirm 1-Click Rollback</DialogTitle>
          </div>
        </DialogHeader>

        <div class="space-y-3 py-2">
          <div v-if="rollbackError" class="p-3 bg-threat/10 border border-threat/30 rounded-lg text-threat text-xs">
            {{ rollbackError }}
          </div>
          <p class="text-sm text-foreground">
            Are you sure you want to rollback to configuration snapshot <strong>v{{ selectedRollbackVersion }}</strong>?
          </p>
          <p class="text-xs text-warning">
            The active live data plane and all cluster nodes will immediately revert to this historical version.
          </p>
        </div>

        <DialogFooter class="flex gap-2 justify-end pt-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            @click="rollbackModalOpen = false"
          >
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            @click="handleRollback"
            :disabled="rollingBack"
            class="bg-warning hover:bg-warning/90 text-warning-foreground gap-1.5"
          >
            <RotateCcw class="w-4 h-4 text-warning-foreground" />
            <span>{{ rollingBack ? 'Reverting...' : 'Confirm Rollback' }}</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
