<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from '@/router'
import { useConfigStore } from '@/stores/config'
import type { Site } from '@/api/client'
import SiteDialog from '@/components/SiteDialog.vue'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table'
import { ConfirmDialog } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { Plus, Globe, Edit2, Trash2, ShieldCheck, Eye, PowerOff, Server, Bot } from 'lucide-vue-next'

const router = useRouter()
const configStore = useConfigStore()

const dialogOpen = ref(false)
const editingSite = ref<Site | null>(null)
const siteToDelete = ref<string | null>(null)
const showDeleteConfirm = ref(false)

const openAddDialog = () => {
  editingSite.value = null
  dialogOpen.value = true
}

const openEditDialog = (site: Site) => {
  editingSite.value = site
  dialogOpen.value = true
}

const handleSaveSite = async (siteData: Partial<Site>) => {
  if (siteData.id) {
    await configStore.updateSite(siteData.id, siteData)
  } else {
    await configStore.createSite(siteData)
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
</script>

<template>
  <div class="h-full flex flex-col space-y-6 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-border shrink-0">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <Globe class="w-5 h-5 text-primary" />
          <span>Protected Sites & Upstream Pools</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Reverse proxy routes, upstream balancing, health check probes, and operational run modes.
        </p>
      </div>

      <Button
        @click="openAddDialog"
        class="gap-1.5"
      >
        <Plus class="w-4 h-4" />
        <span>Add Protected Site</span>
      </Button>
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
        <Button
          @click="openAddDialog"
          class="gap-1.5"
        >
          <Plus class="w-4 h-4" />
          <span>Add Protected Site</span>
        </Button>
      </EmptyState>

      <Table v-else container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="text-xs uppercase font-semibold">Application Site</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Hostnames</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Operational Mode</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Upstream Targets</TableHead>
            <TableHead class="text-right text-xs uppercase font-semibold">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="site in configStore.sites" :key="site.id">
            <TableCell class="font-medium text-foreground text-sm">
              {{ site.name }}
            </TableCell>
            <TableCell>
              <div class="flex flex-wrap gap-1.5">
                <span
                  v-for="host in site.hostnames"
                  :key="host"
                  class="px-2 py-0.5 bg-primary/10 border border-primary/30 rounded text-xs text-primary font-mono"
                >
                  {{ host }}
                </span>
              </div>
            </TableCell>
            <TableCell>
              <Badge
                v-if="site.mode === 'defense'"
                variant="success"
                class="gap-1 font-mono uppercase text-xs"
              >
                <ShieldCheck class="w-3.5 h-3.5 text-success" />
                <span>Defense</span>
              </Badge>
              <Badge
                v-else-if="site.mode === 'audit'"
                variant="info"
                class="gap-1 font-mono uppercase text-xs"
              >
                <Eye class="w-3.5 h-3.5 text-info" />
                <span>Audit</span>
              </Badge>
              <Badge
                v-else
                variant="threat"
                class="gap-1 font-mono uppercase text-xs"
              >
                <PowerOff class="w-3.5 h-3.5 text-threat" />
                <span>Offline (503)</span>
              </Badge>
            </TableCell>
            <TableCell>
              <span class="text-muted-foreground font-mono text-xs">
                {{ site.upstreams?.length || 0 }} target{{ (site.upstreams?.length || 0) === 1 ? '' : 's' }}
              </span>
            </TableCell>
            <TableCell class="text-right space-x-1">
              <TooltipProvider :delay-duration="150">
                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="ghost"
                      size="icon"
                      data-testid="site-bot-protect"
                      class="h-7 w-7 text-muted-foreground hover:text-foreground"
                      @click="openBotProtect(site)"
                    >
                      <Bot class="w-3.5 h-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <p class="text-xs">Bot Protection</p>
                  </TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="ghost"
                      size="icon"
                      class="h-7 w-7 text-muted-foreground hover:text-foreground"
                      @click="openEditDialog(site)"
                    >
                      <Edit2 class="w-3.5 h-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <p class="text-xs">Edit Site</p>
                  </TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="ghost"
                      size="icon"
                      class="h-7 w-7 text-muted-foreground hover:text-threat"
                      @click="confirmDeleteSite(site.id)"
                    >
                      <Trash2 class="w-3.5 h-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <p class="text-xs">Delete Site</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Site Edit / Create Dialog -->
    <SiteDialog
      :open="dialogOpen"
      :site="editingSite"
      @close="dialogOpen = false"
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
