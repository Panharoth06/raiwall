<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { detectionApi, type DetectionRulePack } from '@/api/detection';
import { useAuthStore } from '@/stores/auth';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/dialog';
import { EmptyState } from '@/components/ui/empty-state';
import AdminOnly from '@/components/auth/AdminOnly.vue';
import DetectionHeroBanner from '@/components/detection/DetectionHeroBanner.vue';
import { useHeroBanner } from '@/components/detection/useHeroBanner';
import DetectionPageHeader from '@/components/detection/DetectionPageHeader.vue';
import RulePackTable from '@/components/detection/RulePackTable.vue';
import RulePackImportModal from '@/components/detection/RulePackImportModal.vue';
import { HelpCircle, Package, RefreshCw, Sparkles, Upload } from 'lucide-vue-next';

const auth = useAuthStore();
const canEdit = computed(() => auth.user?.role !== 'viewer');

const { showHero, toggleHero, dismissHero } = useHeroBanner('detection-packs');
const packs = ref<DetectionRulePack[]>([]);
const loading = ref(true);
const saving = ref(false);
const error = ref('');
const pending = ref<Set<string>>(new Set());
const showImport = ref(false);
const deleteTarget = ref<DetectionRulePack | null>(null);

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    packs.value = (await detectionApi.listPacks()).packs;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load rule packs';
  } finally {
    loading.value = false;
  }
};

const mark = (id: string, active: boolean) => {
  const next = new Set(pending.value);
  if (active) next.add(id);
  else next.delete(id);
  pending.value = next;
};

const toggle = async (pack: DetectionRulePack, enabled: boolean) => {
  mark(pack.id, true);
  saving.value = true;
  error.value = '';
  try {
    await detectionApi.updatePack(pack.id, { enabled });
    await load();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to update pack';
  } finally {
    mark(pack.id, false);
    saving.value = false;
  }
};

const confirmDelete = (pack: DetectionRulePack) => {
  deleteTarget.value = pack;
};

const remove = async () => {
  const target = deleteTarget.value;
  if (!target) return;
  mark(target.id, true);
  saving.value = true;
  error.value = '';
  try {
    await detectionApi.deletePack(target.id);
    deleteTarget.value = null;
    await load();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to delete pack';
  } finally {
    mark(target.id, false);
    saving.value = false;
  }
};

const onImportSaved = () => {
  showImport.value = false;
  load();
};

onMounted(load);
</script>

<template>
  <div class="space-y-4 font-sans flex flex-col h-full min-h-0">
    <DetectionPageHeader
      title="Rule Packs"
      description="Installed signature packs and their execution state."
      :icon="Package"
      class="shrink-0"
    >
      <template #actions>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :data-testid="'hero-toggle-packs'"
          @click="toggleHero"
        >
          <HelpCircle class="w-3.5 h-3.5 text-primary" />
          <span>{{ showHero ? 'Hide Guide' : 'Explain feature' }}</span>
        </Button>
        <AdminOnly>
          <Button size="sm" class="h-8 text-xs gap-1.5" @click="showImport = true">
            <Upload class="w-3.5 h-3.5" />
            <span>Import pack</span>
          </Button>
        </AdminOnly>
        <Button size="sm" variant="outline" class="h-8 text-xs gap-1.5" :disabled="loading" @click="load">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          <span>Refresh</span>
        </Button>
      </template>
    </DetectionPageHeader>

    <!-- Prominent Hero Section with Low-Opacity Background Icon -->
    <DetectionHeroBanner
      storage-key="detection-packs"
      title="WAF Rule Packs & External Plugin System"
      badge="EXTERNAL EXTENSIONS"
      description="Rule packs function as modular plugins that expand Raiwall beyond its built-in detection engines. You can install standard ModSecurity (.conf) directive files, full OWASP Coraza Core Rule Set (CRS) bundles, or native JSON signature files. Packs can be toggled on or off instantly with zero gateway downtime."
      :icon="Package"
      :highlights="[
        { label: 'Multi-Format Support', text: 'Import Native JSON, ModSecurity SecRule syntax, or full OWASP CRS bundles.' },
        { label: 'Zero-Downtime Reload', text: 'Packs hot-reload immediately via atomic pointer swap into active memory.' },
        { label: 'Safe Execution Order', text: 'Evaluates before or additive to core AST modules without slowing down safe traffic.' },
      ]"
      v-model:open="showHero"
      @dismiss="dismissHero"
      class="shrink-0"
    />

    <div
      v-if="error"
      class="flex items-center justify-between gap-3 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-xs text-threat shrink-0"
      data-testid="packs-error"
    >
      <span class="truncate">{{ error }}</span>
      <Button size="sm" variant="outline" class="h-7 text-xs shrink-0" @click="load">Retry</Button>
    </div>

    <div v-if="loading" class="space-y-2 shrink-0">
      <div v-for="n in 4" :key="n" class="h-10 rounded-md bg-muted/50 animate-pulse" />
    </div>

    <div v-else-if="packs.length === 0" class="rounded-lg border border-border bg-card shrink-0">
      <EmptyState
        :icon="Package"
        title="No rule packs installed"
        description="Import a JSON signature pack to evaluate custom virtual patches ahead of the semantic funnel."
      >
        <AdminOnly>
          <Button size="sm" variant="outline" class="h-8 text-xs" @click="showImport = true">
            Import first pack
          </Button>
        </AdminOnly>
      </EmptyState>
    </div>

    <div v-else class="grow min-h-0 overflow-auto rounded-lg border border-border bg-card">
      <RulePackTable
        :packs="packs"
        :can-edit="canEdit"
        :pending="pending"
        @toggle="toggle"
        @remove="confirmDelete"
      />
    </div>

    <ConfirmDialog
      :open="deleteTarget !== null"
      title="Delete rule pack"
      :description="deleteTarget ? `Remove ${deleteTarget.name} and all of its rules from the active snapshot?` : ''"
      confirm-text="Delete pack"
      variant="destructive"
      :loading="saving"
      @confirm="remove"
      @cancel="deleteTarget = null"
      @update:open="(value) => { if (!value) deleteTarget = null; }"
    />

    <RulePackImportModal :open="showImport" @close="showImport = false" @saved="onImportSaved" />
  </div>
</template>
