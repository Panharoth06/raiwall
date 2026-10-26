<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api, type Site } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Loader2, Globe, RotateCcw } from 'lucide-vue-next';

interface SiteRow {
  site: Site;
  enabled: boolean;
  bypass: string;
  saving: boolean;
}

const rows = ref<SiteRow[]>([]);
const loading = ref(true);
const error = ref('');

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    const sites = await api.listSites();
    rows.value = sites.map((site) => ({
      site,
      enabled: !!site.auth_enabled,
      bypass: (site.auth_bypass_paths || []).join(', '),
      saving: false,
    }));
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load sites';
  } finally {
    loading.value = false;
  }
};

onMounted(load);

const resetRow = (row: SiteRow) => {
  row.enabled = !!row.site.auth_enabled;
  row.bypass = (row.site.auth_bypass_paths || []).join(', ');
};

const saveRow = async (row: SiteRow) => {
  row.saving = true;
  error.value = '';
  try {
    const bypass = row.bypass
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const updated = await api.updateSite(row.site.id, {
      auth_enabled: row.enabled,
      auth_bypass_paths: bypass,
    });
    row.site = updated;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to update gate';
    resetRow(row);
  } finally {
    row.saving = false;
  }
};
</script>

<template>
  <div class="flex flex-col h-full space-y-3">
    <p class="text-xs text-muted-foreground shrink-0" data-testid="sso-summary">
      {{ rows.filter((r) => r.enabled).length }} of {{ rows.length }} sites enforce the HTTP 467 portal — one directory clearance
      (sl_jwt_session) grants access across every protected app
    </p>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="sso-error">{{ error }}</p>

    <div v-if="loading" class="flex-1 min-h-[200px] flex items-center justify-center space-x-2 text-xs text-muted-foreground" data-testid="sso-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading sites…</span>
    </div>

    <div v-else-if="rows.length === 0" class="flex-1 flex flex-col items-center justify-start pt-10 pb-12 space-y-1 text-center" data-testid="sso-empty">
      <Globe class="w-8 h-8 text-muted-foreground/60 mb-2" />
      <span class="text-base font-semibold text-foreground">No sites registered</span>
      <span class="text-xs text-muted-foreground">Gate enforcement is configured per site once sites are created.</span>
    </div>

    <div v-else class="space-y-2 overflow-auto flex-1">
      <div
        v-for="(row, i) in rows"
        :key="row.site.id"
        class="border border-border rounded-lg p-3 bg-background space-y-2"
        :data-testid="`sso-row-${i}`"
      >
        <div class="flex items-center justify-between gap-3">
          <div class="min-w-0">
            <span class="text-xs font-medium">{{ row.site.name }}</span>
            <span class="ml-2 text-xs font-mono text-muted-foreground">{{ row.site.hostnames.join(' · ') }}</span>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="text-xs font-mono" :class="row.enabled ? 'text-success' : 'text-muted-foreground'" :data-testid="`sso-state-${i}`">
              {{ row.enabled ? 'enforced' : 'open' }}
            </span>
            <button
              :data-testid="`sso-toggle-${i}`"
              class="text-xs font-sans px-2 py-0.5 rounded border border-border hover:bg-muted"
              :disabled="row.saving"
              @click="row.enabled = !row.enabled"
            >
              {{ row.enabled ? 'Turn off' : 'Turn on' }}
            </button>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <span class="text-xs uppercase tracking-wider text-muted-foreground shrink-0 w-24">Bypass paths</span>
          <Input
            v-model="row.bypass"
            placeholder="/health, /assets"
            class="h-7 text-xs font-mono"
            :data-testid="`sso-bypass-${i}`"
          />
          <Button variant="ghost" size="sm" class="h-7 px-1.5 shrink-0" :data-testid="`sso-reset-${i}`" :disabled="row.saving" @click="resetRow(row)">
            <RotateCcw class="w-3.5 h-3.5" />
          </Button>
          <Button
            size="sm"
            class="h-7 shrink-0 text-xs"
            :data-testid="`sso-apply-${i}`"
            :disabled="row.saving || (row.enabled === !!row.site.auth_enabled && row.bypass === (row.site.auth_bypass_paths || []).join(', '))"
            @click="saveRow(row)"
          >
            {{ row.saving ? 'Saving…' : 'Apply' }}
          </Button>
        </div>
      </div>
    </div>
  </div>
</template>
