<script setup lang="ts">
import { ref, computed } from 'vue';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { identityApi, type IdentityUser } from '@/api/identity';

export interface UserDialogResult {
  created: boolean;
  enrollment?: { totp_secret?: string; totp_provisioning_uri?: string };
}

const props = defineProps<{
  open: boolean;
  user: IdentityUser | null;
  apps: { id: string; name: string }[];
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'saved', result: UserDialogResult): void;
}>();

const username = ref('');
const password = ref('');
const email = ref('');
const displayName = ref('');
const enabled = ref(true);
const assignedApps = ref<Record<string, boolean>>({});
const submitting = ref(false);
const error = ref('');

const isCreate = computed(() => !props.user);

const initForm = () => {
  error.value = '';
  if (props.user) {
    username.value = props.user.username;
    email.value = props.user.email;
    displayName.value = props.user.display_name;
    enabled.value = props.user.enabled;
    password.value = '';
    assignedApps.value = Object.fromEntries(props.apps.map((a) => [a.id, props.user!.app_ids.includes(a.id)]));
  } else {
    username.value = '';
    password.value = '';
    email.value = '';
    displayName.value = '';
    enabled.value = true;
    assignedApps.value = {};
  }
};

const selectedAppIds = () => props.apps.filter((a) => assignedApps.value[a.id]).map((a) => a.id);

const submit = async () => {
  error.value = '';
  if (!username.value.trim()) {
    error.value = 'Username is required.';
    return;
  }
  if (isCreate.value && (password.value.length < 8)) {
    error.value = 'Password must be at least 8 characters.';
    return;
  }
  submitting.value = true;
  try {
    if (isCreate.value) {
      const enrollment = await identityApi.createUser({
        username: username.value.trim(),
        password: password.value,
        email: email.value.trim(),
        display_name: displayName.value.trim(),
        app_ids: selectedAppIds(),
      });
      emit('saved', { created: true, enrollment: { totp_secret: enrollment.totp_secret, totp_provisioning_uri: enrollment.totp_provisioning_uri } });
    } else if (props.user) {
      await identityApi.updateUser(props.user.id, {
        email: email.value.trim(),
        display_name: displayName.value.trim(),
        enabled: enabled.value,
        app_ids: selectedAppIds(),
      });
      if (password.value) {
        await identityApi.resetUserPassword(props.user.id, password.value);
      }
      emit('saved', { created: false });
    }
    emit('close');
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Save failed';
  } finally {
    submitting.value = false;
  }
};

defineExpose({ initForm, selectedAppIds, error, submitting });
</script>

<template>
  <Dialog :open="open" @update:open="(v: boolean) => !v && emit('close')">
    <DialogContent class="max-w-sm" data-testid="user-dialog">
      <DialogHeader>
        <DialogTitle>{{ isCreate ? 'Add Directory User' : `Edit ${user?.username}` }}</DialogTitle>
        <DialogDescription>
          {{ isCreate ? 'Directory accounts authenticate against protected sites through the HTTP 467 portal.' : 'Update profile, app bindings, or rotate the password.' }}
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-3">
        <div class="space-y-1" data-testid="user-dialog-username">
          <span class="text-xs font-medium text-muted-foreground">Username</span>
          <Input v-model="username" :disabled="!isCreate" placeholder="walter" class="font-mono text-xs" autocomplete="off" />
        </div>
        <div class="space-y-1" data-testid="user-dialog-password">
          <span class="text-xs font-medium text-muted-foreground">{{ isCreate ? 'Password' : 'New Password (blank = keep)' }}</span>
          <Input v-model="password" type="password" :required="isCreate" placeholder="min 8 chars" class="text-xs" autocomplete="new-password" />
        </div>
        <div class="space-y-1">
          <span class="text-xs font-medium text-muted-foreground">Email</span>
          <Input v-model="email" type="email" placeholder="user@corp.example" class="text-xs" autocomplete="off" />
        </div>
        <div class="space-y-1">
          <span class="text-xs font-medium text-muted-foreground">Display Name</span>
          <Input v-model="displayName" placeholder="Walter Ops" class="text-xs" autocomplete="off" />
        </div>

        <div v-if="apps.length" class="space-y-1" data-testid="user-dialog-apps">
          <span class="text-xs font-medium text-muted-foreground">App Assignments</span>
          <div class="space-y-1.5 border border-border rounded-md p-2 max-h-32 overflow-auto">
            <div v-for="app in apps" :key="app.id" class="flex items-center justify-between gap-2">
              <span class="text-xs font-mono truncate" :title="app.id">{{ app.name }}</span>
              <Switch :model-value="assignedApps[app.id] ?? false" @update:model-value="(v: boolean) => (assignedApps[app.id] = v)" :data-testid="`user-app-toggle-${app.id}`" />
            </div>
          </div>
        </div>

        <div v-if="!isCreate" class="flex items-center justify-between" data-testid="user-dialog-enabled">
          <span class="text-xs font-medium text-muted-foreground">Account Enabled</span>
          <Switch :model-value="enabled" @update:model-value="(v: boolean) => (enabled = v)" data-testid="user-enabled-switch" />
        </div>

        <p v-if="error" class="text-xs text-destructive" data-testid="user-dialog-error">{{ error }}</p>
      </div>

      <DialogFooter>
        <Button variant="outline" size="sm" data-testid="user-dialog-cancel" @click="emit('close')">Cancel</Button>
        <Button size="sm" :disabled="submitting" data-testid="user-dialog-save" @click="submit">
          {{ isCreate ? 'Create User' : 'Save Changes' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
