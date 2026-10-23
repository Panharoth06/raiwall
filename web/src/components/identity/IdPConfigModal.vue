<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from '@/components/ui/select';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import type { IdentityProvider } from '@/api/identity';

type ProviderType = IdentityProvider['type'];

export interface IdPConfigResult {
  type: ProviderType;
  name: string;
  config: Record<string, string>;
}

const props = defineProps<{
  open: boolean;
  provider: IdentityProvider | null;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', result: IdPConfigResult): void;
}>();

const PROVIDER_LABELS: { value: ProviderType; label: string }[] = [
  { value: 'oidc', label: 'OIDC / SSO Federation' },
  { value: 'ldap', label: 'LDAP Directory' },
  { value: 'github', label: 'GitHub OAuth2' },
];

const type = ref<ProviderType>('oidc');
const name = ref('');
const fields = ref<Record<string, string>>({});
const enabled = ref(true);
const error = ref('');
const submitting = ref(false);

const isCreate = computed(() => !props.provider);

const FIELD_DEFS: Record<ProviderType, { key: string; label: string; placeholder: string; required?: boolean; secret?: boolean }[]> = {
  oidc: [
    { key: 'issuer_url', label: 'Issuer URL', placeholder: 'https://sso.corp.example/realms/main', required: true },
    { key: 'client_id', label: 'Client ID', placeholder: 'raiwall-gateway', required: true },
    { key: 'client_secret', label: 'Client Secret', placeholder: '', required: true, secret: true },
    { key: 'redirect_url', label: 'Redirect URL', placeholder: 'https://gateway.corp.example/.raiwall/auth/callback' },
  ],
  ldap: [
    { key: 'host_url', label: 'Host URL', placeholder: 'ldaps://dc01.corp.example:636', required: true },
    { key: 'bind_dn', label: 'Bind DN', placeholder: 'cn=svc-raiwall,dc=corp,dc=example' },
    { key: 'bind_password', label: 'Bind Password', placeholder: '', secret: true },
    { key: 'user_base_dn', label: 'User Base DN', placeholder: 'ou=people,dc=corp,dc=example', required: true },
    { key: 'user_filter', label: 'User Filter', placeholder: '(uid=%s)', required: true },
  ],
  github: [
    { key: 'client_id', label: 'Client ID', placeholder: 'Iv1.xxxx', required: true },
    { key: 'client_secret', label: 'Client Secret', placeholder: '', required: true, secret: true },
    { key: 'redirect_url', label: 'Redirect URL', placeholder: 'https://gateway.corp.example/.raiwall/auth/callback' },
  ],
};

const currentFields = computed(() => FIELD_DEFS[type.value]);

// validate mirrors the backend connector checks (fail-fast, same rules).
const validate = (): string => {
  if (!name.value.trim()) return 'Provider name is required.';
  for (const f of currentFields.value) {
    if (f.required && !fields.value[f.key]?.trim()) {
      return `${f.label} is required.`;
    }
  }
  if (type.value === 'ldap') {
    if (!fields.value.host_url?.includes('://')) {
      return 'Host URL must include the ldap:// or ldaps:// scheme.';
    }
    const filter = fields.value.user_filter ?? '';
    if (!filter.includes('%s')) {
      return 'User Filter must contain the %s username placeholder.';
    }
  }
  return '';
};

const resetForm = () => {
  error.value = '';
  if (props.provider) {
    type.value = props.provider.type;
    name.value = props.provider.name;
    const raw = props.provider.config as Record<string, unknown>;
    fields.value = Object.fromEntries(
      currentFields.value.map((f) => [f.key, typeof raw[f.key] === 'string' ? String(raw[f.key]) : '']),
    );
  } else {
    type.value = 'oidc';
    name.value = '';
    fields.value = {};
    enabled.value = true;
  }
};

watch(() => props.open, (open) => {
  if (open) resetForm();
});

const onSave = () => {
  error.value = '';
  const msg = validate();
  if (msg) {
    error.value = msg;
    return;
  }
  const config: Record<string, string> = {};
  for (const f of currentFields.value) {
    if (fields.value[f.key]) config[f.key] = fields.value[f.key];
  }
  emit('save', { type: type.value, name: name.value.trim(), config });
};

// View-level helpers so programmatic flows (mainly the console tests) can
// drive type selection and naming without the radix Select portal.
const switchType = (value: ProviderType) => {
  type.value = value;
};
const setName = (value: string) => {
  name.value = value;
};

defineExpose({ validate, resetForm, switchType, setName, error, submitting });
</script>

<template>
  <Dialog :open="open" @update:open="(v: boolean) => !v && emit('close')">
    <DialogContent class="max-w-md" data-testid="idp-dialog">
      <DialogHeader>
        <DialogTitle>{{ isCreate ? 'Add Identity Provider' : `Edit ${provider?.name}` }}</DialogTitle>
        <DialogDescription>
          Connector parameters are verified against the directory backend before save.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-3">
        <div class="space-y-1" data-testid="idp-dialog-type">
          <span class="text-xs font-medium text-muted-foreground">Type</span>
          <Select v-model="type" :disabled="!isCreate">
            <SelectTrigger class="h-7 text-xs" data-testid="idp-type-trigger">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="p in PROVIDER_LABELS" :key="p.value" :value="p.value">{{ p.label }}</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div class="space-y-1" data-testid="idp-dialog-name">
          <span class="text-xs font-medium text-muted-foreground">Name</span>
          <Input v-model="name" placeholder="Corporate SSO" class="text-xs" autocomplete="off" />
        </div>

        <div v-for="f in currentFields" :key="f.key" class="space-y-1" :data-testid="`idp-field-${f.key}`">
          <span class="text-xs font-medium text-muted-foreground">{{ f.label }}</span>
          <Input
            v-model="fields[f.key]"
            :type="f.secret ? 'password' : 'text'"
            :placeholder="f.placeholder"
            class="text-xs"
            autocomplete="off"
          />
        </div>

        <div v-if="!isCreate" class="flex items-center justify-between" data-testid="idp-dialog-enabled">
          <span class="text-xs font-medium text-muted-foreground">Enabled</span>
          <Switch v-model="enabled" data-testid="idp-enabled-switch" />
        </div>

        <p v-if="error" class="text-xs text-destructive" data-testid="idp-dialog-error">{{ error }}</p>
      </div>

      <DialogFooter>
        <Button variant="outline" size="sm" data-testid="idp-dialog-cancel" @click="emit('close')">Cancel</Button>
        <Button size="sm" :disabled="submitting" data-testid="idp-dialog-save" @click="onSave">
          {{ isCreate ? 'Add Provider' : 'Save Changes' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
