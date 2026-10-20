<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { Site } from '@/api/client';
import SiteDialog from '@/components/SiteDialog.vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Plus, Globe, Edit2, Trash2, ShieldCheck, Eye, PowerOff, Server } from 'lucide-vue-next';

const configStore = useConfigStore();

const dialogOpen = ref(false);
const editingSite = ref<Site | null>(null);

const openAddDialog = () => {
  editingSite.value = null;
  dialogOpen.value = true;
};

const openEditDialog = (site: Site) => {
  editingSite.value = site;
  dialogOpen.value = true;
};

const handleSaveSite = async (siteData: Partial<Site>) => {
  if (siteData.id) {
    await configStore.updateSite(siteData.id, siteData);
  } else {
    await configStore.createSite(siteData);
  }
};

const handleDeleteSite = async (id: string) => {
  if (confirm('Are you sure you want to remove this site from the draft configuration?')) {
    await configStore.deleteSite(id);
  }
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-[#0d0f14] text-zinc-100 rounded-xl border border-zinc-800 shadow-2xl font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-white flex items-center gap-2">
          <Globe class="w-4 h-4 text-slate-400" />
          <span>Protected Sites & Upstream Pools</span>
        </h1>
        <p class="text-[11px] text-zinc-400 mt-0.5">
          Reverse proxy routes, upstream balancing, health check probes, and operational run modes.
        </p>
      </div>

      <Button
        @click="openAddDialog"
        class="gap-1.5"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>Add Protected Site</span>
      </Button>
    </div>

    <!-- Sites Table Container -->
    <div class="flex-1 min-h-0 bg-[#12151c] border border-zinc-800 rounded-lg overflow-y-auto">
      <div v-if="configStore.sites.length === 0" class="p-12 text-center">
        <Server class="w-10 h-10 text-slate-400 mx-auto mb-3" />
        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-300">No protected sites configured</h3>
        <p class="text-[11px] text-slate-400 mt-1 mb-4">
          Add your first application site to start proxying and inspecting inbound traffic.
        </p>
        <Button
          @click="openAddDialog"
          class="gap-1.5"
        >
          <Plus class="w-3.5 h-3.5" />
          <span>Add Protected Site</span>
        </Button>
      </div>

      <Table v-else>
        <TableHeader class="sticky top-0 z-10 bg-[#14171d]">
          <TableRow>
            <TableHead class="font-mono text-[11px]">Application Site</TableHead>
            <TableHead class="font-mono text-[11px]">Hostnames</TableHead>
            <TableHead class="font-mono text-[11px]">Operational Mode</TableHead>
            <TableHead class="font-mono text-[11px]">Upstream Targets</TableHead>
            <TableHead class="font-mono text-[11px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="site in configStore.sites" :key="site.id">
            <TableCell class="font-medium text-white">
              {{ site.name }}
            </TableCell>
            <TableCell>
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="host in site.hostnames"
                  :key="host"
                  class="px-2 py-0.5 bg-[#17223B] border border-[#2574F5]/30 rounded text-[11px] text-[#38BDF8] font-mono"
                >
                  {{ host }}
                </span>
              </div>
            </TableCell>
            <TableCell>
              <Badge
                v-if="site.mode === 'defense'"
                variant="emerald"
                class="gap-1 font-mono uppercase"
              >
                <ShieldCheck class="w-3 h-3 text-slate-400" />
                <span>Defense</span>
              </Badge>
              <Badge
                v-else-if="site.mode === 'audit'"
                variant="blue"
                class="gap-1 font-mono uppercase"
              >
                <Eye class="w-3 h-3 text-slate-400" />
                <span>Audit</span>
              </Badge>
              <Badge
                v-else
                variant="rose"
                class="gap-1 font-mono uppercase"
              >
                <PowerOff class="w-3 h-3 text-slate-400" />
                <span>Offline (503)</span>
              </Badge>
            </TableCell>
            <TableCell>
              <span class="text-slate-400 font-mono text-[11px]">
                {{ site.upstreams?.length || 0 }} target{{ (site.upstreams?.length || 0) === 1 ? '' : 's' }}
              </span>
            </TableCell>
            <TableCell class="text-right space-x-1">
              <Button
                variant="ghost"
                size="icon"
                @click="openEditDialog(site)"
                title="Edit site"
                class="h-7 w-7 text-slate-400 hover:text-white"
              >
                <Edit2 class="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                @click="handleDeleteSite(site.id)"
                title="Delete site"
                class="h-7 w-7 text-slate-400 hover:text-red-400"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
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
  </div>
</template>
