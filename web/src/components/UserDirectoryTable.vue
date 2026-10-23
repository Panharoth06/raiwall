<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { identityApi, type IdentityUser } from '@/api/identity';
import { api } from '@/api/client';
import UserDialog, { type UserDialogResult } from '@/components/identity/UserDialog.vue';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { KeyRound, Loader2, Plus, Search, ShieldOff, Trash2, UserRound } from 'lucide-vue-next';

const users = ref<IdentityUser[]>([]);
const apps = ref<{ id: string; name: string }[]>([]);
const loading = ref(true);
const error = ref('');
const search = ref('');
const pending = ref<Set<string>>(new Set());
const dialogOpen = ref(false);
const editingUser = ref<IdentityUser | null>(null);
const enrollment = ref<{ secret?: string; uri?: string } | null>(null);

const loadUsers = async () => {
  try {
    users.value = await identityApi.listUsers();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load directory';
  }
};

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    const sites = await api.listSites();
    apps.value = sites.map((s) => ({ id: s.id, name: s.name }));
    await loadUsers();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load directory';
  } finally {
    loading.value = false;
  }
};

onMounted(load);

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  if (!q) return users.value;
  return users.value.filter((u) =>
    `${u.username} ${u.email} ${u.display_name}`.toLowerCase().includes(q),
  );
});

const siteName = (id: string) => apps.value.find((a) => a.id === id)?.name ?? id;

const openCreate = () => {
  editingUser.value = null;
  dialogOpen.value = true;
};

const openEdit = (user: IdentityUser) => {
  editingUser.value = user;
  dialogOpen.value = true;
};

const onSaved = async (result: UserDialogResult) => {
  dialogOpen.value = false;
  if (result.created && result.enrollment) {
    enrollment.value = {
      secret: result.enrollment.totp_secret || undefined,
      uri: result.enrollment.totp_provisioning_uri || undefined,
    };
  }
  await loadUsers();
};

const toggleEnabled = async (user: IdentityUser, enabled: boolean) => {
  const prev = user.enabled;
  user.enabled = enabled;
  pending.value.add(user.id);
  try {
    await identityApi.updateUser(user.id, { enabled });
  } catch (e) {
    user.enabled = prev;
    error.value = e instanceof Error ? e.message : 'Toggle failed';
  } finally {
    pending.value.delete(user.id);
  }
};

const resetTOTP = async (user: IdentityUser) => {
  pending.value.add(user.id);
  error.value = '';
  try {
    const resp = await identityApi.resetUserTOTP(user.id, !user.totp_enrolled);
    user.totp_enrolled = resp.totp_enrolled;
    if (resp.totp_enrolled && resp.totp_provisioning_uri) {
      enrollment.value = { secret: resp.totp_secret, uri: resp.totp_provisioning_uri };
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'TOTP reset failed';
  } finally {
    pending.value.delete(user.id);
  }
};

const removeUser = async (user: IdentityUser) => {
  pending.value.add(user.id);
  error.value = '';
  try {
    await identityApi.deleteUser(user.id);
    users.value = users.value.filter((u) => u.id !== user.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Delete failed';
  } finally {
    pending.value.delete(user.id);
  }
};
</script>

<template>
  <div class="flex flex-col h-full space-y-3">
    <div class="flex items-center justify-between gap-2 shrink-0">
      <div class="relative flex-1 max-w-64">
        <Search class="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="search" placeholder="Search users…" class="pl-7 text-xs" data-testid="user-search" />
      </div>
      <span class="text-xs text-muted-foreground" data-testid="user-summary">{{ users.length }} / 5000 accounts</span>
      <Button size="sm" data-testid="user-add" @click="openCreate">
        <Plus class="w-3.5 h-3.5" />
        Add User
      </Button>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="user-error">{{ error }}</p>

    <div v-if="loading" class="flex items-center justify-center py-16 space-x-2 text-xs text-muted-foreground" data-testid="user-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading directory…</span>
    </div>

    <div v-else-if="filtered.length === 0" class="flex flex-col items-center justify-center py-16 space-y-2 text-xs text-muted-foreground" data-testid="user-empty">
      <UserRound class="w-5 h-5" />
      <span v-if="search">No users match the search</span>
      <span v-else>Directory is empty — add the first account</span>
    </div>

    <div v-else class="border border-border rounded-lg overflow-auto flex-1 bg-background">
      <table class="w-full text-xs" data-testid="user-table">
        <thead class="bg-muted/50 sticky top-0">
          <tr class="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
            <th class="px-3 py-2 font-medium">Account</th>
            <th class="px-3 py-2 font-medium">Email</th>
            <th class="px-3 py-2 font-medium">Apps</th>
            <th class="px-3 py-2 font-medium">2FA</th>
            <th class="px-3 py-2 font-medium">Enabled</th>
            <th class="px-3 py-2 font-medium text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="font-mono tabular-nums">
          <tr v-for="(u, i) in filtered" :key="u.id" class="border-t border-border hover:bg-muted/40" :data-testid="`user-row-${i}`">
            <td class="px-3 py-1.5">
              <span class="font-medium font-sans">{{ u.display_name || u.username }}</span>
              <span class="ml-2 text-muted-foreground text-[10px]">{{ u.username }}</span>
            </td>
            <td class="px-3 py-1.5 text-muted-foreground">{{ u.email || '—' }}</td>
            <td class="px-3 py-1.5 max-w-40 truncate" :title="u.app_ids.map(siteName).join(', ')">
              {{ u.app_ids.map(siteName).join(', ') || '—' }}
            </td>
            <td class="px-3 py-1.5">
              <Badge :variant="u.totp_enrolled ? 'secondary' : 'outline'" class="text-[10px]" :data-testid="`user-totp-${i}`">
                {{ u.totp_enrolled ? '2FA on' : '2FA off' }}
              </Badge>
            </td>
            <td class="px-3 py-1.5">
              <button
                :data-testid="`user-toggle-${i}`"
                class="text-[10px] font-sans px-2 py-0.5 rounded border"
                :class="u.enabled ? 'border-transparent bg-secondary text-secondary-foreground' : 'border-border text-muted-foreground'"
                :disabled="pending.has(u.id)"
                @click="toggleEnabled(u, !u.enabled)"
              >
                {{ u.enabled ? 'active' : 'locked' }}
              </button>
            </td>
            <td class="px-3 py-1.5 text-right whitespace-nowrap">
              <Button variant="ghost" size="sm" class="h-6 px-1.5" :data-testid="`user-edit-${i}`" @click="openEdit(u)">
                <KeyRound class="w-3.5 h-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-6 px-1.5" :data-testid="`user-totp-reset-${i}`" :disabled="pending.has(u.id)" @click="resetTOTP(u)">
                <ShieldOff class="w-3.5 h-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-6 px-1.5 text-destructive" :data-testid="`user-delete-${i}`" :disabled="pending.has(u.id)" @click="removeUser(u)">
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <UserDialog
      v-if="dialogOpen"
      :open="dialogOpen"
      :user="editingUser"
      :apps="apps"
      @close="dialogOpen = false"
      @saved="onSaved"
    />

    <div v-if="enrollment" class="border border-border rounded-lg p-3 bg-muted/40 text-xs space-y-1" data-testid="totp-enrollment-panel">
      <p class="font-medium">2FA enrolled — scan or store this secret now, it is shown once.</p>
      <p class="font-mono break-all" data-testid="totp-enrollment-secret">{{ enrollment.secret }}</p>
      <p class="font-mono text-[10px] text-muted-foreground break-all">{{ enrollment.uri }}</p>
      <Button variant="outline" size="sm" data-testid="totp-enrollment-dismiss" @click="enrollment = null">Dismiss</Button>
    </div>
  </div>
</template>
