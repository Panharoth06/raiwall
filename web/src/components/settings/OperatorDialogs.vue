<script setup lang="ts">
import { ref } from 'vue';
import { api, type AdminUser } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Copy, Check } from 'lucide-vue-next';

const emit = defineEmits<{ (e: 'changed'): void }>();

const createOpen = ref(false);
const createUsername = ref('');
const createPassword = ref('');
const createRole = ref<'admin' | 'viewer'>('viewer');
const createError = ref('');
const creating = ref(false);

const editOpen = ref(false);
const editTarget = ref<AdminUser | null>(null);
const editRole = ref<'admin' | 'viewer'>('viewer');
const editActive = ref(true);
const editError = ref('');
const saving = ref(false);

const resetOpen = ref(false);
const resetTarget = ref<AdminUser | null>(null);
const resetPassword = ref('');
const resetError = ref('');
const resetting = ref(false);

const credential = ref<{ username: string; password: string } | null>(null);
const copied = ref(false);

const showCredential = (username: string, password: string) => {
  credential.value = { username, password };
  copied.value = false;
};

const closeCredential = () => {
  credential.value = null;
  copied.value = false;
};

const copyCredential = async () => {
  if (!credential.value) return;
  try {
    await navigator.clipboard.writeText(`${credential.value.username}\n${credential.value.password}`);
    copied.value = true;
  } catch {
    copied.value = false;
  }
};

const openCreate = () => {
  createUsername.value = '';
  createPassword.value = '';
  createRole.value = 'viewer';
  createError.value = '';
  createOpen.value = true;
};

const openEdit = (user: AdminUser) => {
  editTarget.value = user;
  editRole.value = user.role;
  editActive.value = user.is_active;
  editError.value = '';
  editOpen.value = true;
};

const openReset = (user: AdminUser) => {
  resetTarget.value = user;
  resetPassword.value = '';
  resetError.value = '';
  resetOpen.value = true;
};

const submitCreate = async () => {
  creating.value = true;
  createError.value = '';
  try {
    const res = await api.createAdminUser({
      username: createUsername.value.trim(),
      password: createPassword.value || undefined,
      role: createRole.value,
    });
    createOpen.value = false;
    if (res.password) showCredential(res.user.username, res.password);
    emit('changed');
  } catch (e) {
    createError.value = e instanceof Error ? e.message : 'Failed to create operator';
  } finally {
    creating.value = false;
  }
};

const submitEdit = async () => {
  if (!editTarget.value) return;
  saving.value = true;
  editError.value = '';
  try {
    await api.updateAdminUser(editTarget.value.id, {
      role: editRole.value,
      is_active: editActive.value,
    });
    editOpen.value = false;
    emit('changed');
  } catch (e) {
    editError.value = e instanceof Error ? e.message : 'Failed to update operator';
  } finally {
    saving.value = false;
  }
};

const submitReset = async () => {
  if (!resetTarget.value) return;
  resetting.value = true;
  resetError.value = '';
  try {
    const res = await api.resetAdminUserPassword(resetTarget.value.id, resetPassword.value || undefined);
    resetOpen.value = false;
    if (res.password) showCredential(res.user.username, res.password);
  } catch (e) {
    resetError.value = e instanceof Error ? e.message : 'Failed to reset password';
  } finally {
    resetting.value = false;
  }
};

defineExpose({ openCreate, openEdit, openReset });
</script>

<template>
  <!-- Create -->
  <Dialog v-model:open="createOpen">
    <DialogContent class="max-w-md">
      <DialogHeader>
        <DialogTitle>Add operator</DialogTitle>
      </DialogHeader>
      <div class="space-y-3 py-2">
        <div>
          <label for="operator-username" class="mb-1 block text-sm font-medium text-foreground">Username</label>
          <Input id="operator-username" v-model="createUsername" autocomplete="off" placeholder="alice" />
        </div>
        <div>
          <label class="mb-1 block text-sm font-medium text-foreground">Role</label>
          <Select v-model="createRole">
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="viewer">Viewer (read-only)</SelectItem>
              <SelectItem value="admin">Admin (full control)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label for="operator-password" class="mb-1 block text-sm font-medium text-foreground">Password</label>
          <Input
            id="operator-password"
            v-model="createPassword"
            type="password"
            autocomplete="new-password"
            placeholder="Leave empty to generate"
          />
        </div>
        <p v-if="createError" class="text-sm text-threat">{{ createError }}</p>
      </div>
      <DialogFooter>
        <Button variant="outline" size="sm" @click="createOpen = false">Cancel</Button>
        <Button size="sm" :disabled="creating || !createUsername.trim()" @click="submitCreate">
          {{ creating ? 'Creating…' : 'Create operator' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>

  <!-- Edit -->
  <Dialog v-model:open="editOpen">
    <DialogContent class="max-w-md">
      <DialogHeader>
        <DialogTitle>Edit {{ editTarget?.username }}</DialogTitle>
      </DialogHeader>
      <div class="space-y-3 py-2">
        <div>
          <label class="mb-1 block text-sm font-medium text-foreground">Role</label>
          <Select v-model="editRole">
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="viewer">Viewer</SelectItem>
              <SelectItem value="admin">Admin</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <label class="flex items-center justify-between gap-3 text-sm text-foreground">
          <span>Account active</span>
          <Switch v-model:checked="editActive" aria-label="Account active" />
        </label>
        <p v-if="editError" class="text-sm text-threat">{{ editError }}</p>
      </div>
      <DialogFooter>
        <Button variant="outline" size="sm" @click="editOpen = false">Cancel</Button>
        <Button size="sm" :disabled="saving" @click="submitEdit">
          {{ saving ? 'Saving…' : 'Save changes' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>

  <!-- Password reset -->
  <Dialog v-model:open="resetOpen">
    <DialogContent class="max-w-md">
      <DialogHeader>
        <DialogTitle>Reset password for {{ resetTarget?.username }}</DialogTitle>
      </DialogHeader>
      <div class="space-y-3 py-2">
        <div>
          <label for="operator-new-password" class="mb-1 block text-sm font-medium text-foreground">
            New password
          </label>
          <Input
            id="operator-new-password"
            v-model="resetPassword"
            type="password"
            autocomplete="new-password"
            placeholder="Leave empty to generate"
          />
        </div>
        <p class="text-sm text-muted-foreground">All existing sessions for this operator are revoked.</p>
        <p v-if="resetError" class="text-sm text-threat">{{ resetError }}</p>
      </div>
      <DialogFooter>
        <Button variant="outline" size="sm" @click="resetOpen = false">Cancel</Button>
        <Button size="sm" :disabled="resetting" @click="submitReset">
          {{ resetting ? 'Resetting…' : 'Reset password' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>

  <!-- One-time credential -->
  <Dialog :open="credential !== null" @update:open="(open: boolean) => { if (!open) closeCredential(); }">
    <DialogContent class="max-w-md">
      <DialogHeader>
        <DialogTitle>One-time credentials</DialogTitle>
      </DialogHeader>
      <div class="space-y-3 py-2">
        <p class="text-sm text-warning">This password is shown once. Store it before closing.</p>
        <div class="rounded-md border border-border bg-muted p-3 font-mono text-sm text-foreground">
          <div>{{ credential?.username }}</div>
          <div class="break-all">{{ credential?.password }}</div>
        </div>
      </div>
      <DialogFooter>
        <Button variant="outline" size="sm" class="gap-1.5" @click="copyCredential">
          <Check v-if="copied" class="h-3.5 w-3.5" />
          <Copy v-else class="h-3.5 w-3.5" />
          {{ copied ? 'Copied' : 'Copy' }}
        </Button>
        <Button size="sm" @click="closeCredential">Done</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
