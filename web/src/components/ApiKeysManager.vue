<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api, type ApiKeyItem } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NumberInput } from '@/components/ui/number-input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  ConfirmDialog,
} from '@/components/ui/dialog';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Key, Plus, Trash2, Copy, Check } from 'lucide-vue-next';

const keys = ref<ApiKeyItem[]>([]);
const loading = ref(false);

const modalOpen = ref(false);
const newKeyName = ref('');
const newKeyRole = ref<'admin' | 'viewer'>('viewer');
const newKeyExpires = ref(30);

const generatedToken = ref<string | null>(null);
const copied = ref(false);

const loadKeys = async () => {
  loading.value = true;
  try {
    keys.value = await api.listApiKeys();
  } catch {
    // ignore
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadKeys();
});

const createError = ref<string | null>(null);
const keyToDelete = ref<string | null>(null);
const showRevokeConfirm = ref(false);

const handleCreateKey = async () => {
  if (!newKeyName.value) return;
  createError.value = null;
  try {
    const res = await api.createApiKey({
      name: newKeyName.value,
      role: newKeyRole.value,
      expires_in_days: newKeyExpires.value,
    });
    generatedToken.value = res.token;
    await loadKeys();
  } catch (err: unknown) {
    createError.value = err instanceof Error ? err.message : 'Failed to create API key';
  }
};

const copyToken = () => {
  if (generatedToken.value) {
    navigator.clipboard.writeText(generatedToken.value);
    copied.value = true;
    setTimeout(() => {
      copied.value = false;
    }, 2000);
  }
};

const confirmRevokeKey = (id: string) => {
  keyToDelete.value = id;
  showRevokeConfirm.value = true;
};

const executeRevokeKey = async () => {
  if (keyToDelete.value) {
    await api.deleteApiKey(keyToDelete.value);
    keyToDelete.value = null;
    await loadKeys();
  }
  showRevokeConfirm.value = false;
};
</script>

<template>
  <div class="space-y-4 font-sans">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-sm font-semibold text-foreground flex items-center space-x-2">
          <Key class="w-4 h-4 text-muted-foreground" />
          <span>Management API & MCP Bearer Keys</span>
        </h3>
        <p class="text-xs text-muted-foreground mt-0.5">
          Authenticate automated CI/CD pipelines, MCP desktop agents, and external scripts.
        </p>
      </div>

      <Button
        @click="modalOpen = true; generatedToken = null;"
        class="gap-1.5"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>Generate API Key</span>
      </Button>
    </div>

    <!-- Keys Table Container -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <EmptyState
        v-if="keys.length === 0"
        :icon="Key"
        title="No active API keys found"
        description="Generate a key to access the Huma REST API or MCP server."
        class="py-8"
      />

      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead class="text-xs uppercase font-semibold">Key Name</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Prefix</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Role</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Created</TableHead>
            <TableHead class="text-right text-xs uppercase font-semibold">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="key in keys" :key="key.id">
            <TableCell class="font-medium text-foreground text-sm">{{ key.name }}</TableCell>
            <TableCell class="font-mono text-primary text-xs">{{ key.prefix }}...</TableCell>
            <TableCell>
              <Badge
                :variant="key.role === 'admin' ? 'warning' : 'secondary'"
                class="font-mono uppercase tracking-wider text-xs"
              >
                {{ key.role }}
              </Badge>
            </TableCell>
            <TableCell class="text-muted-foreground text-xs">{{ new Date(key.created_at).toLocaleDateString() }}</TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                @click="confirmRevokeKey(key.id)"
                class="h-7 w-7 text-muted-foreground hover:text-threat"
                title="Revoke key"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Generate Key Modal -->
    <Dialog :open="modalOpen" @update:open="modalOpen = $event">
      <DialogContent class="max-w-md">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <Key class="w-5 h-5 text-muted-foreground" />
            <DialogTitle>Generate API Bearer Token</DialogTitle>
          </div>
        </DialogHeader>

        <div v-if="createError" class="p-3 bg-threat/10 border border-threat/30 rounded-lg text-threat text-xs">
          {{ createError }}
        </div>

        <div class="py-2 space-y-4">
          <div v-if="!generatedToken">
            <div class="space-y-3">
              <div>
                <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Key Name</label>
                <Input
                  v-model="newKeyName"
                  placeholder="e.g. CI/CD Deployer or Claude Desktop"
                />
              </div>

              <div>
                <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">RBAC Role</label>
                <Select v-model="newKeyRole">
                  <SelectTrigger class="w-full h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="viewer">Viewer (Read-only status & metrics)</SelectItem>
                    <SelectItem value="admin">Admin (Read/Write mutating operations)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Expiration (Days)</label>
                <NumberInput
                  v-model="newKeyExpires"
                  :min="1"
                  :max="365"
                  suffix="days"
                />
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="secondary"
                @click="modalOpen = false"
              >
                Cancel
              </Button>
              <Button
                type="button"
                @click="handleCreateKey"
              >
                Generate Token
              </Button>
            </DialogFooter>
          </div>

          <div v-else class="space-y-4">
            <div class="p-3 bg-warning/10 border border-warning/30 rounded-lg text-xs text-warning">
              <strong>Make sure to copy your API key now.</strong> You won't be able to see it again!
            </div>

            <div class="relative">
              <Input
                readonly
                :model-value="generatedToken"
                class="text-primary font-mono text-xs pr-10"
              />
              <Button
                variant="ghost"
                size="icon"
                @click="copyToken"
                class="absolute right-1 top-1 h-7 w-7 text-muted-foreground hover:text-foreground"
                title="Copy to clipboard"
              >
                <component :is="copied ? Check : Copy" class="w-4 h-4" />
              </Button>
            </div>

            <DialogFooter class="flex justify-end pt-2 border-t border-border">
              <Button
                type="button"
                @click="modalOpen = false"
              >
                Done
              </Button>
            </DialogFooter>
          </div>
        </div>
      </DialogContent>
    </Dialog>

    <!-- Revoke Confirmation Modal -->
    <ConfirmDialog
      v-model:open="showRevokeConfirm"
      title="Revoke API Key"
      description="Revoke this API key? Applications and pipelines using it will lose access immediately."
      confirm-text="Revoke Key"
      variant="destructive"
      @confirm="executeRevokeKey"
      @cancel="showRevokeConfirm = false"
    />
  </div>
</template>
