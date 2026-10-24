<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type ForwardingRule, type Upstream, type Site } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Switch } from '@/components/ui/switch';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { Plus, Pencil, Trash2, Loader2, Split } from 'lucide-vue-next';

const props = defineProps<{ site: Site }>();

const rules = ref<ForwardingRule[]>([]);
const loading = ref(true);
const error = ref('');
const pending = ref(false);
const modalOpen = ref(false);
const editingRule = ref<ForwardingRule | null>(null);

const prefix = ref('');
const upstreamsText = ref('');
const stripPrefix = ref(false);
const hostOverride = ref('');
const isActive = ref(true);
const ruleError = ref('');

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    rules.value = await api.listForwardingRules(props.site.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load forwarding rules';
  } finally {
    loading.value = false;
  }
};

onMounted(load);

const upstreamSummary = (rule: ForwardingRule): string =>
  (rule.upstreams || []).map((u: Upstream) => u.dial).join(', ') || '—';

const openCreate = () => {
  editingRule.value = null;
  prefix.value = '';
  upstreamsText.value = '';
  stripPrefix.value = false;
  hostOverride.value = '';
  isActive.value = true;
  ruleError.value = '';
  modalOpen.value = true;
};

const openEdit = (rule: ForwardingRule) => {
  editingRule.value = rule;
  prefix.value = rule.prefix;
  upstreamsText.value = (rule.upstreams || []).map((u) => u.dial).join(', ');
  stripPrefix.value = rule.strip_prefix;
  hostOverride.value = rule.host_header_override;
  isActive.value = rule.is_active;
  ruleError.value = '';
  modalOpen.value = true;
};

function parseUpstreams(raw: string): Upstream[] {
  return raw
    .split(',')
    .map((s) => s.trim().replace(/^https?:\/\//, ''))
    .filter(Boolean)
    .map((dial) => ({ dial, weight: 1 }));
}

const validate = (): string => {
  if (!prefix.value.startsWith('/')) return 'Prefix must start with "/".';
  if (parseUpstreams(upstreamsText.value).length === 0) {
    return 'At least one upstream target (host:port) is required.';
  }
  return '';
};

const save = async () => {
  ruleError.value = validate();
  if (ruleError.value) return;
  pending.value = true;
  error.value = '';
  try {
    const payload = {
      prefix: prefix.value,
      upstreams: parseUpstreams(upstreamsText.value),
      strip_prefix: stripPrefix.value,
      host_header_override: hostOverride.value.trim(),
      is_active: isActive.value,
    };
    if (editingRule.value) {
      await api.updateForwardingRule(props.site.id, editingRule.value.id, payload);
    } else {
      await api.createForwardingRule(props.site.id, payload);
    }
    modalOpen.value = false;
    await load();
  } catch (e) {
    ruleError.value = e instanceof Error ? e.message : 'Save failed';
  } finally {
    pending.value = false;
  }
};

const removeRule = async (rule: ForwardingRule) => {
  error.value = '';
  try {
    await api.deleteForwardingRule(props.site.id, rule.id);
    rules.value = rules.value.filter((r) => r.id !== rule.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Delete failed';
  }
};

const activeCount = computed(() => rules.value.filter((r) => r.is_active).length);
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-center justify-between">
      <span class="text-xs text-muted-foreground" data-testid="fwd-summary">
        {{ activeCount }} of {{ rules.length }} path prefixes routing to dedicated upstream pools
      </span>
      <Button size="sm" data-testid="fwd-add" @click="openCreate">
        <Plus class="w-3.5 h-3.5" />
        Add Rule
      </Button>
    </div>

    <p v-if="error" class="text-xs text-destructive" data-testid="fwd-error">{{ error }}</p>

    <div v-if="loading" class="flex items-center justify-center py-12 space-x-2 text-xs text-muted-foreground" data-testid="fwd-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading routing rules…</span>
    </div>

    <div v-else-if="rules.length === 0" class="flex flex-col items-center justify-center py-12 space-y-2 text-xs text-muted-foreground" data-testid="fwd-empty">
      <Split class="w-5 h-5" />
      <span>No path-prefix rules — all traffic flows to the default upstream pool</span>
    </div>

    <div v-else class="overflow-auto rounded-lg border border-border bg-card">
      <Table data-testid="fwd-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Prefix</TableHead>
            <TableHead>Upstream Pool</TableHead>
            <TableHead>Strip Prefix</TableHead>
            <TableHead>Host Override</TableHead>
            <TableHead>State</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums">
          <TableRow v-for="(rule, i) in rules" :key="rule.id" :data-testid="`fwd-row-${i}`">
            <TableCell class="font-medium">{{ rule.prefix }}</TableCell>
            <TableCell class="text-muted-foreground">{{ upstreamSummary(rule) }}</TableCell>
            <TableCell>{{ rule.strip_prefix ? 'yes' : 'no' }}</TableCell>
            <TableCell>{{ rule.host_header_override || '—' }}</TableCell>
            <TableCell>
              <Badge :variant="rule.is_active ? 'secondary' : 'outline'" class="text-[10px]">
                {{ rule.is_active ? 'active' : 'paused' }}
              </Badge>
            </TableCell>
            <TableCell class="whitespace-nowrap text-right">
              <Button variant="ghost" size="sm" class="h-6 px-1.5" :data-testid="`fwd-edit-${i}`" @click="openEdit(rule)">
                <Pencil class="w-3.5 h-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-6 px-1.5 text-destructive" :data-testid="`fwd-delete-${i}`" @click="removeRule(rule)">
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <Dialog :open="modalOpen" @update:open="(v: boolean) => (modalOpen = v)">
      <DialogContent class="max-w-sm" data-testid="fwd-dialog">
        <DialogHeader>
          <DialogTitle>{{ editingRule ? 'Edit Forwarding Rule' : 'Add Forwarding Rule' }}</DialogTitle>
          <DialogDescription>Path prefixes route matched requests to a dedicated upstream pool before the default pool.</DialogDescription>
        </DialogHeader>
        <div class="space-y-3">
          <div class="space-y-1" data-testid="fwd-dialog-prefix">
            <span class="text-xs font-medium text-muted-foreground">Path Prefix</span>
            <Input v-model="prefix" placeholder="/api/v2" class="font-mono text-xs" autocomplete="off" />
          </div>
          <div class="space-y-1" data-testid="fwd-dialog-upstreams">
            <span class="text-xs font-medium text-muted-foreground">Upstream Targets (comma-separated)</span>
            <Input v-model="upstreamsText" placeholder="10.0.0.12:8080, 10.0.0.13:8080" class="font-mono text-xs" autocomplete="off" />
          </div>
          <div class="space-y-1" data-testid="fwd-dialog-host">
            <span class="text-xs font-medium text-muted-foreground">Host Header Override (optional)</span>
            <Input v-model="hostOverride" placeholder="internal-api.local" class="font-mono text-xs" autocomplete="off" />
          </div>
          <div class="flex items-center justify-between" data-testid="fwd-dialog-strip">
            <span class="text-xs font-medium text-muted-foreground">Strip Prefix Upstream</span>
            <Switch v-model="stripPrefix" data-testid="fwd-strip-switch" />
          </div>
          <div class="flex items-center justify-between" data-testid="fwd-dialog-active">
            <span class="text-xs font-medium text-muted-foreground">Rule Active</span>
            <Switch v-model="isActive" data-testid="fwd-active-switch" />
          </div>
          <p v-if="ruleError" class="text-xs text-destructive" data-testid="fwd-dialog-error">{{ ruleError }}</p>
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" data-testid="fwd-dialog-cancel" @click="modalOpen = false">Cancel</Button>
          <Button size="sm" :disabled="pending" data-testid="fwd-dialog-save" @click="save">
            {{ editingRule ? 'Save Rule' : 'Add Rule' }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
