<script setup lang="ts">
import { ref, watch } from 'vue';
import { api, type ExceptionRule } from '@/api/client';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Play, ShieldAlert, ShieldCheck } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  rule?: ExceptionRule | null;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
}>();

const testHost = ref('api.example.com');
const testPath = ref('/v1/search');
const testMethod = ref('GET');
const testParamName = ref('query');
const testParamVal = ref("' OR 1=1 --");

const testing = ref(false);
const result = ref<{ matched: boolean; reason: string } | null>(null);

watch(
  () => props.rule,
  (val) => {
    if (val) {
      testHost.value = val.host || 'api.example.com';
      testPath.value = val.path || '/v1/search';
      testMethod.value = val.method || 'GET';
      testParamName.value = val.param_name || 'query';
    }
    result.value = null;
  },
  { immediate: true }
);

const runSimulation = async () => {
  testing.value = true;
  result.value = null;
  try {
    const res = await api.dryRunException({
      rule: props.rule || {
        host: testHost.value,
        path: testPath.value,
        method: testMethod.value,
        location: 'query',
        param_name: testParamName.value,
        rule_id: 'ALL',
      },
      request: {
        host: testHost.value,
        path: testPath.value,
        method: testMethod.value,
        params: { [testParamName.value]: testParamVal.value },
      },
    });
    result.value = res;
  } catch (err: unknown) {
    result.value = {
      matched: false,
      reason: err instanceof Error ? err.message : 'Simulation failed',
    };
  } finally {
    testing.value = false;
  }
};

const handleOpenChange = (openState: boolean) => {
  if (!openState) {
    emit('close');
  }
};
</script>

<template>
  <Dialog :open="open" @update:open="handleOpenChange">
    <DialogContent class="max-w-xl">
      <!-- Header -->
      <DialogHeader>
        <div class="flex items-center space-x-2.5">
          <Play class="w-5 h-5 text-muted-foreground" />
          <DialogTitle>Exception Rule Test Simulator</DialogTitle>
        </div>
      </DialogHeader>

      <!-- Body -->
      <div class="py-2 space-y-4">
        <p class="text-xs text-muted-foreground">
          Test synthetic HTTP parameters against this exception rule to confirm false-positive suppression before deployment.
        </p>

        <div class="grid grid-cols-3 gap-3">
          <div>
            <label class="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Method</label>
            <Select v-model="testMethod">
              <SelectTrigger class="w-full h-9">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="GET">GET</SelectItem>
                <SelectItem value="POST">POST</SelectItem>
                <SelectItem value="PUT">PUT</SelectItem>
                <SelectItem value="DELETE">DELETE</SelectItem>
              </SelectContent>
            </Select>
            <select v-model="testMethod" class="sr-only" tabindex="-1" aria-hidden="true">
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          <div class="col-span-2">
            <label class="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Host Header</label>
            <Input
              v-model="testHost"
              placeholder="api.example.com"
            />
          </div>
        </div>

        <div>
          <label class="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Request Path</label>
          <Input
            v-model="testPath"
            placeholder="/v1/search"
          />
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Param Name</label>
            <Input
              v-model="testParamName"
              placeholder="query"
            />
          </div>

          <div>
            <label class="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Test Payload</label>
            <Input
              v-model="testParamVal"
              placeholder="' OR 1=1 --"
            />
          </div>
        </div>

        <!-- Simulation Output Box -->
        <div v-if="result" class="p-3.5 rounded-lg border text-xs" :class="result.matched ? 'bg-success/10 border-success/30' : 'bg-threat/10 border-threat/30'">
          <div class="flex items-center space-x-2 font-semibold" :class="result.matched ? 'text-success' : 'text-threat'">
            <ShieldCheck v-if="result.matched" class="w-4 h-4 text-success" />
            <ShieldAlert v-else class="w-4 h-4 text-threat" />
            <span>{{ result.matched ? 'Suppression Matched (Traffic Allowed)' : 'No Match (Threat Blocked)' }}</span>
          </div>
          <p class="mt-1 text-foreground text-[11px] font-mono">{{ result.reason }}</p>
        </div>
      </div>

      <!-- Footer -->
      <DialogFooter>
        <Button
          type="button"
          variant="secondary"
          @click="$emit('close')"
        >
          Close
        </Button>
        <Button
          type="button"
          :disabled="testing"
          @click="runSimulation"
          class="gap-1.5"
        >
          <Play class="w-3.5 h-3.5" />
          <span>{{ testing ? 'Evaluating...' : 'Run Dry-Run Test' }}</span>
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
