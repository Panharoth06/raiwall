<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useRoute } from '@/router';
import { useConfigStore } from '@/stores/config';
import type { ExceptionRule } from '@/api/client';
import ExceptionTestModal from '@/components/ExceptionTestModal.vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
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
import { Plus, Shield, Trash2, Play, Sparkles, Save } from 'lucide-vue-next';

const configStore = useConfigStore();

const showAddModal = ref(false);
const testModalOpen = ref(false);
const selectedRuleForTest = ref<ExceptionRule | null>(null);

const newHost = ref('');
const newPath = ref('');
const newMethod = ref('ALL');
const newLocation = ref('query');
const newParamName = ref('');
const newReason = ref('');
const newRuleId = ref('ALL');

const openAddModal = () => {
  newHost.value = '';
  newPath.value = '';
  newMethod.value = 'ALL';
  newLocation.value = 'query';
  newParamName.value = '';
  newReason.value = '';
  newRuleId.value = 'ALL';
  showAddModal.value = true;
};

const route = useRoute();

const checkQueryAndOpen = () => {
  if (route.value?.query?.create === 'true') {
    newHost.value = route.value.query.host || '';
    newPath.value = route.value.query.path || '';
    newMethod.value = route.value.query.method || 'ALL';
    newLocation.value = route.value.query.location || 'query';
    newParamName.value = route.value.query.param || '*';
    newReason.value = 'Created from live attack inspector';
    newRuleId.value = route.value.query.rule_id || 'ALL';
    showAddModal.value = true;
  }
};

onMounted(() => {
  checkQueryAndOpen();
});

watch(() => route.value?.query, () => {
  checkQueryAndOpen();
});

const handleSaveException = async () => {
  if (!newPath.value || !newParamName.value) {
    alert('Path and Parameter Name are required');
    return;
  }

  await configStore.createException({
    host: newHost.value || '*',
    path: newPath.value,
    method: newMethod.value,
    location: newLocation.value,
    param_name: newParamName.value,
    reason: newReason.value || 'False-positive suppression',
    rule_id: newRuleId.value || 'ALL',
  });

  showAddModal.value = false;
};

const openTestSimulator = (rule: ExceptionRule) => {
  selectedRuleForTest.value = rule;
  testModalOpen.value = true;
};

const handleDelete = async (id: string) => {
  if (confirm('Delete this exception rule?')) {
    await configStore.deleteException(id);
  }
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Shield class="w-4 h-4 text-muted-foreground" />
          <span>False-Positive Exception Rules</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Granular parameter-level bypasses: Host + Path + Method + Location + Param Name.
        </p>
      </div>

      <Button
        @click="openAddModal"
        class="gap-1.5"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>Add Exception Rule</span>
      </Button>
    </div>

    <!-- Exceptions Table Container -->
    <div class="flex-1 min-h-0 bg-card border border-border rounded-lg overflow-y-auto">
      <div v-if="configStore.exceptions.length === 0" class="p-12 text-center">
        <Sparkles class="w-10 h-10 text-muted-foreground mx-auto mb-3" />
        <h3 class="text-xs font-semibold uppercase tracking-wider text-foreground">No exception rules defined</h3>
        <p class="text-sm text-muted-foreground mt-1 mb-4 leading-relaxed">
          Suppress false-positives without disabling the WAF globally.
        </p>
        <Button
          @click="openAddModal"
          class="gap-1.5"
        >
          <Plus class="w-3.5 h-3.5" />
          <span>Add First Exception</span>
        </Button>
      </div>

      <Table v-else container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Host / Path</TableHead>
            <TableHead>Method</TableHead>
            <TableHead>Location</TableHead>
            <TableHead>Parameter Name</TableHead>
            <TableHead>Suppressed Threat</TableHead>
            <TableHead>Reason</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="rule in configStore.exceptions" :key="rule.id">
            <TableCell>
              <span class="text-foreground font-medium block font-mono">{{ rule.path }}</span>
              <span class="text-[10px] text-muted-foreground font-mono">{{ rule.host || '*' }}</span>
            </TableCell>
            <TableCell class="font-mono text-[11px]">
              <span class="px-2 py-0.5 bg-primary/10 border border-primary/30 rounded text-primary">
                {{ rule.method }}
              </span>
            </TableCell>
            <TableCell>
              <span class="capitalize text-foreground font-mono text-[11px]">{{ rule.location }}</span>
            </TableCell>
            <TableCell class="font-mono text-success font-semibold">
              {{ rule.param_name }}
            </TableCell>
            <TableCell class="font-mono text-muted-foreground text-[11px]">
              {{ rule.rule_id || 'ALL' }}
            </TableCell>
            <TableCell class="text-muted-foreground truncate max-w-xs text-[11px]">
              {{ rule.reason }}
            </TableCell>
            <TableCell class="text-right space-x-1">
              <Button
                variant="ghost"
                size="icon"
                @click="openTestSimulator(rule)"
                title="Test with simulator"
                class="h-7 w-7 text-muted-foreground hover:text-foreground"
              >
                <Play class="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                @click="handleDelete(rule.id)"
                title="Delete exception"
                class="h-7 w-7 text-muted-foreground hover:text-threat"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Add Exception Modal -->
    <Dialog :open="showAddModal" @update:open="showAddModal = $event">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <div class="flex items-center space-x-2.5">
            <Shield class="w-5 h-5 text-muted-foreground" />
            <DialogTitle>New Parameter Exception Rule</DialogTitle>
          </div>
        </DialogHeader>

        <div class="space-y-4 py-2">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Host (Optional)</label>
              <Input
                v-model="newHost"
                placeholder="* or api.example.com"
              />
            </div>
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Path</label>
              <Input
                v-model="newPath"
                placeholder="/api/v1/search"
              />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">HTTP Method</label>
              <Select v-model="newMethod">
                <SelectTrigger class="w-full h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">ALL</SelectItem>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                </SelectContent>
              </Select>
              <select v-model="newMethod" class="sr-only" tabindex="-1" aria-hidden="true">
                <option value="ALL">ALL</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Parameter Location</label>
              <Select v-model="newLocation">
                <SelectTrigger class="w-full h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="query">Query Parameter</SelectItem>
                  <SelectItem value="header">Request Header</SelectItem>
                  <SelectItem value="cookie">Cookie</SelectItem>
                  <SelectItem value="body">Request Body</SelectItem>
                </SelectContent>
              </Select>
              <select v-model="newLocation" class="sr-only" tabindex="-1" aria-hidden="true">
                <option value="query">Query Parameter</option>
                <option value="header">Request Header</option>
                <option value="cookie">Cookie</option>
                <option value="body">Request Body</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Parameter Name</label>
              <Input
                v-model="newParamName"
                placeholder="e.g. search_term"
              />
            </div>
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Rule ID (or ALL)</label>
              <Input
                v-model="newRuleId"
                placeholder="ALL or SQLI_*"
              />
            </div>
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Reason / Context</label>
            <Input
              v-model="newReason"
              placeholder="e.g. Valid SQL editor payload in internal tool"
            />
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="secondary"
            @click="showAddModal = false"
          >
            Cancel
          </Button>
          <Button
            type="button"
            @click="handleSaveException"
            class="gap-1.5"
          >
            <Save class="w-3.5 h-3.5" />
            <span>Add to Draft</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Test Simulator Modal -->
    <ExceptionTestModal
      :open="testModalOpen"
      :rule="selectedRuleForTest"
      @close="testModalOpen = false"
    />
  </div>
</template>
