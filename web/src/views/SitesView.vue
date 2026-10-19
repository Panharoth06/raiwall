<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { Site } from '@/api/client';
import SiteDialog from '@/components/SiteDialog.vue';
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
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight flex items-center space-x-2.5">
          <Globe class="w-6 h-6 text-emerald-400" />
          <span>Protected Sites & Upstream Pools</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">
          Configure protected domains, reverse proxy upstream pools, and application run modes.
        </p>
      </div>

      <button
        @click="openAddDialog"
        class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-2"
      >
        <Plus class="w-4 h-4" />
        <span>Add Protected Site</span>
      </button>
    </div>

    <!-- Sites Table -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      <div v-if="configStore.sites.length === 0" class="p-12 text-center">
        <Server class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 class="text-sm font-semibold text-slate-300">No protected sites configured</h3>
        <p class="text-xs text-slate-500 mt-1 mb-4">
          Add your first application site to start proxying and inspecting inbound traffic.
        </p>
        <button
          @click="openAddDialog"
          class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors"
        >
          Add Protected Site
        </button>
      </div>

      <table v-else class="w-full text-left text-xs text-slate-300">
        <thead class="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
          <tr>
            <th class="py-3 px-4">Application Site</th>
            <th class="py-3 px-4">Hostnames</th>
            <th class="py-3 px-4">Operational Mode</th>
            <th class="py-3 px-4">Upstream Targets</th>
            <th class="py-3 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/60">
          <tr v-for="site in configStore.sites" :key="site.id" class="hover:bg-slate-800/40 transition-colors">
            <td class="py-3.5 px-4 font-medium text-white">
              {{ site.name }}
            </td>
            <td class="py-3.5 px-4">
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="host in site.hostnames"
                  :key="host"
                  class="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-[11px] text-slate-300 font-mono"
                >
                  {{ host }}
                </span>
              </div>
            </td>
            <td class="py-3.5 px-4">
              <span
                v-if="site.mode === 'defense'"
                class="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              >
                <ShieldCheck class="w-3 h-3" />
                <span>Defense</span>
              </span>
              <span
                v-else-if="site.mode === 'audit'"
                class="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30"
              >
                <Eye class="w-3 h-3" />
                <span>Audit</span>
              </span>
              <span
                v-else
                class="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30"
              >
                <PowerOff class="w-3 h-3" />
                <span>Offline (503)</span>
              </span>
            </td>
            <td class="py-3.5 px-4">
              <span class="text-slate-400">
                {{ site.upstreams?.length || 0 }} target{{ (site.upstreams?.length || 0) === 1 ? '' : 's' }}
              </span>
            </td>
            <td class="py-3.5 px-4 text-right space-x-2">
              <button
                @click="openEditDialog(site)"
                class="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors"
                title="Edit site"
              >
                <Edit2 class="w-4 h-4" />
              </button>
              <button
                @click="handleDeleteSite(site.id)"
                class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                title="Delete site"
              >
                <Trash2 class="w-4 h-4" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
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
