<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { identityApi, type IdentityProvider } from '@/api/identity';
import IdPConfigModal, { type IdPConfigResult } from '@/components/identity/IdPConfigModal.vue';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Trash2, Loader2, PlugZap, Plus, Pencil } from 'lucide-vue-next';

const providers = ref<IdentityProvider[]>([]);
const loading = ref(true);
const error = ref('');
const pending = ref<Set<string>>(new Set());
const modalOpen = ref(false);
const editingProvider = ref<IdentityProvider | null>(null);

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    providers.value = await identityApi.listProviders();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load identity providers';
  } finally {
    loading.value = false;
  }
};

onMounted(load);

const openCreate = () => {
  editingProvider.value = null;
  modalOpen.value = true;
};

const openEdit = (provider: IdentityProvider) => {
  editingProvider.value = provider;
  modalOpen.value = true;
};

const onSave = async (result: IdPConfigResult) => {
  error.value = '';
  pending.value.add('__modal');
  try {
    if (editingProvider.value) {
      await identityApi.updateProvider(editingProvider.value.id, {
        name: result.name,
        config: result.config,
      });
    } else {
      await identityApi.createProvider(result);
    }
    modalOpen.value = false;
    await load();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Save failed';
    // Keep the modal open so the operator sees the backend rejection.
  } finally {
    pending.value.delete('__modal');
  }
};

const toggleProvider = async (provider: IdentityProvider) => {
  pending.value.add(provider.id);
  error.value = '';
  try {
    await identityApi.updateProvider(provider.id, { enabled: !provider.enabled });
    provider.enabled = !provider.enabled;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Toggle failed';
  } finally {
    pending.value.delete(provider.id);
  }
};

const removeProvider = async (provider: IdentityProvider) => {
  pending.value.add(provider.id);
  error.value = '';
  try {
    await identityApi.deleteProvider(provider.id);
    providers.value = providers.value.filter((p) => p.id !== provider.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Delete failed';
  } finally {
    pending.value.delete(provider.id);
  }
};

const configSummary = (provider: IdentityProvider): string => {
  const cfg = provider.config as Record<string, unknown>;
  const first = Object.entries(cfg).find(([key]) => !key.includes('secret') && !key.includes('password'));
  return first ? `${first[0]}: ${String(first[1])}` : `${Object.keys(cfg).length} parameters`;
};
</script>

<template>
  <div class="flex flex-col h-full space-y-3">
    <div class="flex items-center justify-between shrink-0">
      <span class="text-xs text-muted-foreground" data-testid="idp-summary">
        {{ providers.length }} connector{{ providers.length === 1 ? '' : 's' }} — login portals cascade through every enabled directory
      </span>
      <Button size="sm" data-testid="idp-add" @click="openCreate">
        <Plus class="w-3.5 h-3.5" />
        Add Provider
      </Button>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="idp-error">{{ error }}</p>

    <div v-if="loading" class="flex items-center justify-center py-16 space-x-2 text-xs text-muted-foreground" data-testid="idp-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading connectors…</span>
    </div>

    <div v-else-if="providers.length === 0" class="flex flex-col items-center justify-center py-16 space-y-2 text-xs text-muted-foreground" data-testid="idp-empty">
      <PlugZap class="w-5 h-5" />
      <span>No external directory connected — the built-in account directory serves logins</span>
      <span class="text-[10px]">OIDC, LDAP (ldap:// / ldaps://), and GitHub OAuth2 are supported</span>
    </div>

    <div v-else class="space-y-2 overflow-auto flex-1">
      <div v-for="(p, i) in providers" :key="p.id" class="border border-border rounded-lg p-3 bg-background" :data-testid="`idp-row-${i}`">
        <div class="flex items-center justify-between gap-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <span class="text-xs font-medium truncate">{{ p.name }}</span>
              <Badge variant="secondary" class="text-[10px] font-mono">{{ p.type }}</Badge>
              <Badge v-if="!p.enabled" variant="outline" class="text-[10px]">disabled</Badge>
            </div>
            <p class="text-[10px] font-mono text-muted-foreground truncate mt-0.5">{{ configSummary(p) }}</p>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <Button variant="ghost" size="sm" class="h-6 px-1.5" :data-testid="`idp-toggle-${i}`" :disabled="pending.has(p.id)" @click="toggleProvider(p)">
              {{ p.enabled ? 'Disable' : 'Enable' }}
            </Button>
            <Button variant="ghost" size="sm" class="h-6 px-1.5" :data-testid="`idp-edit-${i}`" @click="openEdit(p)">
              <Pencil class="w-3.5 h-3.5" />
            </Button>
            <Button variant="ghost" size="sm" class="h-6 px-1.5 text-destructive" :data-testid="`idp-delete-${i}`" :disabled="pending.has(p.id)" @click="removeProvider(p)">
              <Trash2 class="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      </div>
    </div>

    <IdPConfigModal
      v-if="modalOpen"
      :open="modalOpen"
      :provider="editingProvider"
      @close="modalOpen = false"
      @save="onSave"
    />
  </div>
</template>
