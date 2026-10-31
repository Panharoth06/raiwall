<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api, type AdminUser } from '@/api/client';
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
import { ConfirmDialog } from '@/components/ui/dialog';
import { EmptyState } from '@/components/ui/empty-state';
import OperatorDialogs from './OperatorDialogs.vue';
import { Plus, Users } from 'lucide-vue-next';

const users = ref<AdminUser[]>([]);
const loading = ref(true);
const error = ref('');
const actionError = ref('');
const pendingId = ref<string | null>(null);
const dialogs = ref<InstanceType<typeof OperatorDialogs> | null>(null);

const confirmOpen = ref(false);
const confirmKind = ref<'deactivate' | 'revoke'>('deactivate');
const confirmTarget = ref<AdminUser | null>(null);

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    users.value = await api.listAdminUsers();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load operators';
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  void load();
});

const formatDate = (value: string) => new Date(value).toLocaleString();

const roleClass = (role: string) =>
  role === 'admin' ? 'border-primary/40 text-primary bg-primary/10' : 'text-muted-foreground';

const openConfirm = (kind: 'deactivate' | 'revoke', user: AdminUser) => {
  confirmKind.value = kind;
  confirmTarget.value = user;
  confirmOpen.value = true;
};

const confirmTitle = () =>
  confirmKind.value === 'deactivate' ? 'Deactivate operator' : 'Revoke operator sessions';
const confirmDescription = () =>
  confirmKind.value === 'deactivate'
    ? `Deactivate ${confirmTarget.value?.username}? They will be signed out and cannot log in.`
    : `Revoke all active sessions for ${confirmTarget.value?.username}? They will need to sign in again.`;
const confirmLabel = () =>
  confirmKind.value === 'deactivate' ? 'Deactivate' : 'Revoke sessions';

const executeConfirm = async () => {
  const target = confirmTarget.value;
  if (!target) return;
  pendingId.value = target.id;
  actionError.value = '';
  try {
    if (confirmKind.value === 'deactivate') {
      await api.deactivateAdminUser(target.id);
    } else {
      await api.revokeAdminUserSessions(target.id);
    }
    confirmOpen.value = false;
    await load();
  } catch (e) {
    actionError.value = e instanceof Error ? e.message : 'Action failed';
  } finally {
    pendingId.value = null;
  }
};
</script>

<template>
  <div class="space-y-4 font-sans">
    <div class="flex items-start justify-between gap-4">
      <div>
        <h2 class="text-base font-semibold tracking-tight text-foreground">Operators</h2>
        <p class="mt-1 text-sm text-muted-foreground">
          Dashboard accounts. Role, password, and status changes revoke existing sessions immediately.
        </p>
      </div>
      <Button size="sm" class="gap-1.5" @click="dialogs?.openCreate()">
        <Plus class="h-3.5 w-3.5" />
        Add operator
      </Button>
    </div>

    <p v-if="actionError" class="rounded-md border border-threat/30 bg-threat/10 p-2.5 text-sm text-threat">
      {{ actionError }}
    </p>

    <div v-if="loading" class="space-y-2" aria-busy="true" aria-label="Loading operators">
      <div v-for="row in 3" :key="row" class="h-10 animate-pulse rounded-md bg-muted" />
    </div>

    <div v-else-if="error" class="rounded-md border border-threat/30 bg-threat/10 p-3 text-sm text-threat">
      <span>{{ error }}</span>
      <Button variant="outline" size="sm" class="ml-2" @click="load">Retry</Button>
    </div>

    <EmptyState
      v-else-if="users.length === 0"
      :icon="Users"
      title="No operators yet"
      description="Create a dashboard account with the admin or viewer role."
    >
      <Button size="sm" class="gap-1.5" @click="dialogs?.openCreate()">
        <Plus class="h-3.5 w-3.5" />
        Add operator
      </Button>
    </EmptyState>

    <Table v-else>
      <TableHeader>
        <TableRow>
          <TableHead>Operator</TableHead>
          <TableHead>Role</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Created</TableHead>
          <TableHead class="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="user in users" :key="user.id">
          <TableCell class="max-w-[16rem] truncate font-mono text-sm text-foreground">
            {{ user.username }}
          </TableCell>
          <TableCell>
            <Badge variant="outline" class="font-mono text-xs uppercase" :class="roleClass(user.role)">
              {{ user.role }}
            </Badge>
          </TableCell>
          <TableCell class="text-sm" :class="user.is_active ? 'text-success' : 'text-muted-foreground'">
            {{ user.is_active ? 'Active' : 'Inactive' }}
          </TableCell>
          <TableCell class="text-xs text-muted-foreground">{{ formatDate(user.created_at) }}</TableCell>
          <TableCell class="text-right">
            <div class="flex justify-end gap-1">
              <Button variant="ghost" size="sm" :disabled="pendingId === user.id" @click="dialogs?.openEdit(user)">
                Edit
              </Button>
              <Button variant="ghost" size="sm" :disabled="pendingId === user.id" @click="dialogs?.openReset(user)">
                Password
              </Button>
              <Button variant="ghost" size="sm" :disabled="pendingId === user.id" @click="openConfirm('revoke', user)">
                Sessions
              </Button>
              <Button
                variant="ghost"
                size="sm"
                class="text-threat"
                :disabled="!user.is_active || pendingId === user.id"
                @click="openConfirm('deactivate', user)"
              >
                Deactivate
              </Button>
            </div>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>

    <ConfirmDialog
      v-model:open="confirmOpen"
      :title="confirmTitle()"
      :description="confirmDescription()"
      :confirm-text="confirmLabel()"
      variant="destructive"
      @confirm="executeConfirm"
      @cancel="confirmOpen = false"
    />

    <OperatorDialogs ref="dialogs" @changed="load" />
  </div>
</template>
