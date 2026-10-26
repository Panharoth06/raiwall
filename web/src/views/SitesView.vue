<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from '@/router'
import { useConfigStore } from '@/stores/config'
import { useAuthStore } from '@/stores/auth'
import type { Site } from '@/api/client'
import SiteDialog from '@/components/SiteDialog.vue'
import SitesTable from '@/components/sites/SitesTable.vue'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { Plus, Globe, Server, AlertTriangle, Loader2 } from 'lucide-vue-next'

const router = useRouter()
const configStore = useConfigStore()
const authStore = useAuthStore()

const dialogOpen = ref(false)
const editingSite = ref<Site | null>(null)
const saving = ref(false)
const saveError = ref<string | null>(null)

const siteToDelete = ref<string | null>(null)
const showDeleteConfirm = ref(false)

const applying = ref(false)
const applyError = ref<string | null>(null)

const openAddDialog = () => {
  editingSite.value = null
  saveError.value = null
  dialogOpen.value = true
}

const openEditDialog = (site: Site) => {
  editingSite.value = site
  saveError.value = null
  dialogOpen.value = true
}

const closeDialog = () => {
  if (saving.value) return
  dialogOpen.value = false
}

const handleSaveSite = async (siteData: Partial<Site>) => {
  saving.value = true
  saveError.value = null
  try {
    if (siteData.id) {
      await configStore.updateSite(siteData.id, siteData)
    } else {
      await configStore.createSite(siteData)
    }
    await configStore.loadCertificates()
    dialogOpen.value = false
  } catch (err: unknown) {
    saveError.value = err instanceof Error ? err.message : 'Failed to save the application'
  } finally {
    saving.value = false
  }
}

const applyNow = async () => {
  applying.value = true
  applyError.value = null
  try {
    await configStore.applyDraft(authStore.user?.username || 'admin', 'Applied from sites view')
  } catch (err: unknown) {
    applyError.value = err instanceof Error ? err.message : 'Apply failed'
  } finally {
    applying.value = false
  }
}

const openBotProtect = (site: Site) => {
  void router.push(`/anti-bot?app=${encodeURIComponent(site.id)}`)
}

const confirmDeleteSite = (id: string) => {
  siteToDelete.value = id
  showDeleteConfirm.value = true
}

const executeDeleteSite = async () => {
  if (siteToDelete.value) {
    await configStore.deleteSite(siteToDelete.value)
    siteToDelete.value = null
  }
  showDeleteConfirm.value = false
}

const pendingCount = computed(() => configStore.diffs.length)
</script>

<template>
  <div class="h-full flex flex-col space-y-6 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-border shrink-0">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <Globe class="w-5 h-5 text-primary" />
          <span>Protected Sites &amp; Upstream Pools</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Routing mode, TLS termination, upstream balancing, and operational run mode per application.
        </p>
      </div>

      <Button class="gap-1.5" @click="openAddDialog">
        <Plus class="w-4 h-4" />
        <span>Add Protected Site</span>
      </Button>
    </div>

    <!-- Pending changes -->
    <div
      v-if="pendingCount > 0"
      data-testid="sites-pending-banner"
      class="flex flex-wrap items-center gap-3 px-3 py-2 rounded-md border border-warning/30 bg-warning/5 shrink-0"
    >
      <AlertTriangle class="w-4 h-4 text-warning shrink-0" />
      <span class="text-xs text-warning font-medium">
        {{ pendingCount }} staged change{{ pendingCount === 1 ? '' : 's' }} not serving traffic yet
      </span>
      <span v-if="applyError" class="text-xs text-threat">{{ applyError }}</span>
      <div class="ml-auto flex items-center gap-2">
        <Button
          variant="ghost"
          class="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
          @click="router.push('/deployments')"
        >
          Review diff
        </Button>
        <Button
          class="h-7 px-3 text-xs gap-1.5"
          :disabled="applying"
          data-testid="sites-apply-now"
          @click="applyNow"
        >
          <Loader2 v-if="applying" class="w-3.5 h-3.5 animate-spin" />
          <span>{{ applying ? 'Applying…' : 'Apply now' }}</span>
        </Button>
      </div>
    </div>

    <!-- Sites Table Container -->
    <div class="flex-1 min-h-0 bg-card border border-border rounded-lg overflow-y-auto">
      <EmptyState
        v-if="configStore.sites.length === 0"
        :icon="Server"
        title="No protected sites configured"
        description="Add your first application site to start proxying and inspecting inbound traffic."
        class="py-12"
      >
        <Button class="gap-1.5" @click="openAddDialog">
          <Plus class="w-4 h-4" />
          <span>Add Protected Site</span>
        </Button>
      </EmptyState>

      <SitesTable
        v-else
        :sites="configStore.sites"
        :certificates="configStore.certificates"
        @edit="openEditDialog"
        @delete="confirmDeleteSite"
        @bot-protect="openBotProtect"
      />
    </div>

    <!-- Site Edit / Create Dialog -->
    <SiteDialog
      :open="dialogOpen"
      :site="editingSite"
      :certificates="configStore.certificates"
      :submitting="saving"
      :error="saveError"
      @close="closeDialog"
      @save="handleSaveSite"
    />

    <!-- Delete Confirmation Modal -->
    <ConfirmDialog
      v-model:open="showDeleteConfirm"
      title="Delete Protected Site"
      description="Are you sure you want to remove this site from the draft configuration? Traffic forwarding will cease once applied."
      confirm-text="Delete Site"
      variant="destructive"
      @confirm="executeDeleteSite"
      @cancel="showDeleteConfirm = false"
    />
  </div>
</template>
