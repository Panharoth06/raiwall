<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { identityApi, type IdentityUser } from '@/api/identity';
import { api } from '@/api/client';
import UserDialog, { type UserDialogResult } from '@/components/identity/UserDialog.vue';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SearchInput } from '@/components/ui/search-input';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { TablePagination } from '@/components/ui/table-pagination';
import { KeyRound, Loader2, Plus, ShieldOff, Trash2, UserRound } from 'lucide-vue-next';

const users = ref<IdentityUser[]>([]);
const apps = ref<{ id: string; name: string }[]>([]);
const loading = ref(true);
const error = ref('');
const search = ref('');
const pending = ref<Set<string>>(new Set());
const dialogOpen = ref(false);
const editingUser = ref<IdentityUser | null>(null);
const enrollment = ref<{ secret?: string; uri?: string } | null>(null);
const page = ref(1);
const pageSize = ref(20);

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

watch(search, () => {
  page.value = 1;
});

const paginatedUsers = computed(() => {
  const start = (page.value - 1) * pageSize.value;
  return filtered.value.slice(start, start + pageSize.value);
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
  <div class="flex flex-col h-full space-y-4">
    <!-- Action Toolbar -->
    <div class="flex items-center justify-between gap-4 shrink-0">
      <div class="flex items-center gap-3">
        <SearchInput
          v-model="search"
          clearable
          placeholder="Search users…"
          class="w-64"
          data-testid="user-search"
        />
        <span class="text-xs text-muted-foreground font-mono" data-testid="user-summary">
          {{ users.length }} {{ users.length === 1 ? 'account' : 'accounts' }}
        </span>
      </div>
      <Button size="sm" class="gap-1.5" data-testid="user-add" @click="openCreate">
        <Plus class="w-3.5 h-3.5" />
        Add User
      </Button>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="user-error">{{ error }}</p>

    <!-- Table Container (Always rendered with header & borders) -->
    <div class="flex-1 overflow-auto rounded-lg border border-border bg-card">
      <Table data-testid="user-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="w-56">Account</TableHead>
            <TableHead class="w-64">Email</TableHead>
            <TableHead>Apps</TableHead>
            <TableHead class="w-24">2FA</TableHead>
            <TableHead class="w-28">Status</TableHead>
            <TableHead class="w-32 text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums">
          <!-- Loading State -->
          <TableRow v-if="loading">
            <TableCell colspan="6" class="h-64 text-center text-muted-foreground">
              <div class="flex flex-col items-center justify-center p-8 space-y-2" data-testid="user-loading">
                <Loader2 class="w-5 h-5 animate-spin text-primary mx-auto" />
                <span class="text-xs">Loading directory…</span>
              </div>
            </TableCell>
          </TableRow>

          <!-- Empty State -->
          <TableRow v-else-if="filtered.length === 0">
            <TableCell colspan="6" class="h-64 text-center align-middle">
              <div class="flex flex-col items-center justify-center py-10 px-4 space-y-2 text-center" data-testid="user-empty">
                <div class="w-10 h-10 rounded-full bg-muted/50 flex items-center justify-center mb-1">
                  <UserRound class="w-5 h-5 text-muted-foreground/60" />
                </div>
                <div v-if="search" class="text-sm font-semibold text-foreground">No users match the search</div>
                <div v-else class="text-sm font-semibold text-foreground">Directory is empty</div>
                <div class="text-xs text-muted-foreground max-w-sm">
                  {{ search ? 'Try adjusting your search query or clear the filter.' : 'Add user accounts to grant application access credentials.' }}
                </div>
                <Button v-if="!search" size="sm" variant="outline" class="mt-2 text-xs gap-1.5" @click="openCreate">
                  <Plus class="w-3.5 h-3.5" />
                  Add First User
                </Button>
              </div>
            </TableCell>
          </TableRow>

          <!-- User Rows -->
          <TableRow v-else v-for="(u, i) in paginatedUsers" :key="u.id" :data-testid="`user-row-${i}`">
            <TableCell>
              <span class="font-medium font-sans text-foreground">{{ u.display_name || u.username }}</span>
              <span class="ml-2 text-muted-foreground text-xs font-mono">{{ u.username }}</span>
            </TableCell>
            <TableCell class="text-muted-foreground text-xs">{{ u.email || '—' }}</TableCell>
            <TableCell class="max-w-40 truncate text-xs" :title="u.app_ids.map(siteName).join(', ')">
              {{ u.app_ids.map(siteName).join(', ') || '—' }}
            </TableCell>
            <TableCell>
              <Badge :variant="u.totp_enrolled ? 'secondary' : 'outline'" class="text-xs" :data-testid="`user-totp-${i}`">
                {{ u.totp_enrolled ? '2FA on' : '2FA off' }}
              </Badge>
            </TableCell>
            <TableCell>
              <button
                :data-testid="`user-toggle-${i}`"
                class="text-xs font-sans px-2 py-0.5 rounded border cursor-pointer transition-colors"
                :class="u.enabled ? 'border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80' : 'border-border text-muted-foreground hover:bg-muted'"
                :disabled="pending.has(u.id)"
                @click="toggleEnabled(u, !u.enabled)"
              >
                {{ u.enabled ? 'active' : 'locked' }}
              </button>
            </TableCell>
            <TableCell class="text-right whitespace-nowrap">
              <Button variant="ghost" size="sm" class="h-6 px-1.5" title="Edit user" :data-testid="`user-edit-${i}`" @click="openEdit(u)">
                <KeyRound class="w-3.5 h-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-6 px-1.5" title="Reset 2FA" :data-testid="`user-totp-reset-${i}`" :disabled="pending.has(u.id)" @click="resetTOTP(u)">
                <ShieldOff class="w-3.5 h-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-6 px-1.5 text-destructive hover:text-destructive" title="Delete user" :data-testid="`user-delete-${i}`" :disabled="pending.has(u.id)" @click="removeUser(u)">
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <!-- Pagination Footer -->
      <TablePagination
        :page="page"
        :page-size="pageSize"
        :total="filtered.length"
        :page-size-options="[10, 20, 50, 100]"
        item-label="users"
        @update:page="(p) => page = p"
        @update:page-size="(s) => { pageSize = s; page = 1; }"
      />
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
      <p class="font-mono text-xs text-muted-foreground break-all">{{ enrollment.uri }}</p>
      <Button variant="outline" size="sm" data-testid="totp-enrollment-dismiss" @click="enrollment = null">Dismiss</Button>
    </div>
  </div>
</template>
