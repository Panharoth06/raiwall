<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api, type ApiKeyItem } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
} from '@/components/ui/dialog';
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

const handleCreateKey = async () => {
  if (!newKeyName.value) return;
  try {
    const res = await api.createApiKey({
      name: newKeyName.value,
      role: newKeyRole.value,
      expires_in_days: newKeyExpires.value,
    });
    generatedToken.value = res.token;
    await loadKeys();
  } catch (err: unknown) {
    alert(err instanceof Error ? err.message : 'Failed to create API key');
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

const handleDeleteKey = async (id: string) => {
  if (confirm('Revoke this API key? Applications using it will lose access immediately.')) {
    await api.deleteApiKey(id);
    await loadKeys();
  }
};
</script>

<template>
  <div class="space-y-4 font-sans">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-sm font-semibold text-white flex items-center space-x-2">
          <Key class="w-4 h-4 text-slate-400" />
          <span>Management API & MCP Bearer Keys</span>
        </h3>
        <p class="text-xs text-slate-400 mt-0.5">
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
    <div class="bg-[#181b20] border border-[#2d3440] rounded-lg overflow-hidden">
      <div v-if="keys.length === 0" class="p-8 text-center text-xs text-slate-400">
        No active API keys found. Generate a key to access the Huma REST API or MCP server.
      </div>

      <Table v-else>
        <TableHeader class="bg-[#14171d]">
          <TableRow>
            <TableHead class="font-mono text-[11px]">Key Name</TableHead>
            <TableHead class="font-mono text-[11px]">Prefix</TableHead>
            <TableHead class="font-mono text-[11px]">Role</TableHead>
            <TableHead class="font-mono text-[11px]">Created</TableHead>
            <TableHead class="font-mono text-[11px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="key in keys" :key="key.id">
            <TableCell class="font-medium text-white">{{ key.name }}</TableCell>
            <TableCell class="font-mono text-[#38BDF8]">{{ key.prefix }}...</TableCell>
            <TableCell>
              <Badge
                :variant="key.role === 'admin' ? 'amber' : 'secondary'"
                class="font-mono uppercase tracking-wider"
              >
                {{ key.role }}
              </Badge>
            </TableCell>
            <TableCell class="text-slate-400">{{ new Date(key.created_at).toLocaleDateString() }}</TableCell>
            <TableCell class="text-right">
              <Button
                variant="ghost"
                size="icon"
                @click="handleDeleteKey(key.id)"
                class="h-7 w-7 text-slate-400 hover:text-red-400"
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
      <DialogContent class="max-w-md bg-[#1e222a] border-[#2d3440] p-6 font-sans">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <Key class="w-5 h-5 text-slate-400" />
            <DialogTitle>Generate API Bearer Token</DialogTitle>
          </div>
        </DialogHeader>

        <div class="py-2 space-y-4">
          <div v-if="!generatedToken">
            <div class="space-y-3">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Key Name</label>
                <Input
                  v-model="newKeyName"
                  placeholder="e.g. CI/CD Deployer or Claude Desktop"
                />
              </div>

              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">RBAC Role</label>
                <Select v-model="newKeyRole">
                  <SelectTrigger class="w-full h-9 border-[#363D4C] bg-[#15181F] text-xs text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent class="border-[#363D4C] bg-[#1E222A] text-white">
                    <SelectItem value="viewer">Viewer (Read-only status & metrics)</SelectItem>
                    <SelectItem value="admin">Admin (Read/Write mutating operations)</SelectItem>
                  </SelectContent>
                </Select>
                <select v-model="newKeyRole" class="sr-only" tabindex="-1" aria-hidden="true">
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>

              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Expiration (Days)</label>
                <Input
                  v-model.number="newKeyExpires"
                  type="number"
                  min="1"
                  max="365"
                />
              </div>
            </div>

            <DialogFooter class="flex justify-end space-x-2 pt-4 border-t border-[#2d3440]">
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
            <div class="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-300">
              <strong>Make sure to copy your API key now.</strong> You won't be able to see it again!
            </div>

            <div class="relative">
              <Input
                readonly
                :model-value="generatedToken"
                class="text-[#38BDF8] font-mono text-xs pr-10"
              />
              <Button
                variant="ghost"
                size="icon"
                @click="copyToken"
                class="absolute right-1 top-1 h-7 w-7 text-slate-400 hover:text-white"
                title="Copy to clipboard"
              >
                <component :is="copied ? Check : Copy" class="w-4 h-4" />
              </Button>
            </div>

            <DialogFooter class="flex justify-end pt-2 border-t border-[#2d3440]">
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
  </div>
</template>
