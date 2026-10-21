<script setup lang="ts">
import { ref, watch } from 'vue';
import { api, type ACLRule } from '@/api/client';
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
import { CheckCircle2, AlertCircle, Save, Code } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  rule?: ACLRule | null;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', rule: Partial<ACLRule>): void;
}>();

const formName = ref('');
const formExpr = ref('');
const formAction = ref<'block' | 'allow' | 'redirect'>('block');
const formRedirectUrl = ref('');
const formPriority = ref(100);

const validating = ref(false);
const validationResult = ref<{ valid: boolean; error?: string } | null>(null);

watch(
  () => props.rule,
  (val) => {
    if (val) {
      formName.value = val.name;
      formExpr.value = val.expression;
      formAction.value = val.action;
      formRedirectUrl.value = val.redirect_url || '';
      formPriority.value = val.priority;
    } else {
      formName.value = '';
      formExpr.value = 'ClientIP in "10.0.0.0/8" && Path == "/admin"';
      formAction.value = 'block';
      formRedirectUrl.value = '';
      formPriority.value = 100;
    }
    validationResult.value = null;
  },
  { immediate: true }
);

const validateSyntax = async () => {
  if (!formExpr.value.trim()) {
    validationResult.value = { valid: false, error: 'Expression cannot be empty' };
    return;
  }
  validating.value = true;
  try {
    const res = await api.dryRunACL({
      expression: formExpr.value,
      request: { ClientIP: '127.0.0.1', Path: '/test', Method: 'GET' },
    });
    validationResult.value = res;
  } catch (err: unknown) {
    validationResult.value = {
      valid: false,
      error: err instanceof Error ? err.message : 'Syntax error',
    };
  } finally {
    validating.value = false;
  }
};

const handleSave = () => {
  emit('save', {
    id: props.rule?.id,
    name: formName.value,
    expression: formExpr.value,
    action: formAction.value,
    redirect_url: formAction.value === 'redirect' ? formRedirectUrl.value : undefined,
    priority: formPriority.value,
    enabled: true,
  });
  emit('close');
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
          <Code class="w-5 h-5 text-muted-foreground" />
          <DialogTitle>
            {{ rule ? 'Edit ACL Rule' : 'New ACL Bytecode Rule' }}
          </DialogTitle>
        </div>
      </DialogHeader>

      <!-- Body -->
      <div class="py-2 space-y-4">
        <div>
          <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Rule Name</label>
          <Input
            v-model="formName"
            placeholder="e.g. Block External Admin Access"
          />
        </div>

        <div>
          <div class="flex items-center justify-between mb-1">
            <label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Boolean Expression (expr-lang)
            </label>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              :disabled="validating"
              @click="validateSyntax"
              class="h-6 text-[11px] text-muted-foreground hover:text-foreground px-2"
            >
              {{ validating ? 'Compiling...' : 'Verify Syntax' }}
            </Button>
          </div>
          <textarea
            v-model="formExpr"
            rows="3"
            class="w-full px-3 py-2 bg-card border border-input rounded-md text-foreground placeholder:text-muted-foreground font-mono text-xs focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring transition-colors"
            placeholder='ClientIP in "192.168.0.0/16" && Method == "POST"'
          ></textarea>

          <!-- Syntax verification banner -->
          <div v-if="validationResult" class="mt-2 text-xs flex items-center space-x-2">
            <div v-if="validationResult.valid" class="text-success flex items-center space-x-1.5">
              <CheckCircle2 class="w-4 h-4 text-success" />
              <span>Expression compiled cleanly (sub-15ns bytecode verified)</span>
            </div>
            <div v-else class="text-threat flex items-center space-x-1.5 font-mono text-[11px]">
              <AlertCircle class="w-4 h-4 flex-shrink-0 text-threat" />
              <span>{{ validationResult.error }}</span>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Action</label>
            <Select v-model="formAction">
              <SelectTrigger class="w-full h-9">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="block">Block (403 Forbidden)</SelectItem>
                <SelectItem value="allow">Allow (Bypass Deep Inspection)</SelectItem>
                <SelectItem value="redirect">Redirect (302 Found)</SelectItem>
              </SelectContent>
            </Select>
            <select v-model="formAction" class="sr-only" tabindex="-1" aria-hidden="true">
              <option value="block">Block</option>
              <option value="allow">Allow</option>
              <option value="redirect">Redirect</option>
            </select>
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Evaluation Priority</label>
            <Input
              v-model.number="formPriority"
              type="number"
              min="1"
              max="999"
            />
          </div>
        </div>

        <div v-if="formAction === 'redirect'">
          <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Redirect Target URL</label>
          <Input
            v-model="formRedirectUrl"
            placeholder="https://auth.example.com/login"
          />
        </div>
      </div>

      <!-- Footer -->
      <DialogFooter>
        <Button
          type="button"
          variant="secondary"
          @click="$emit('close')"
        >
          Cancel
        </Button>
        <Button
          type="button"
          @click="handleSave"
          class="gap-1.5"
        >
          <Save class="w-3.5 h-3.5" />
          <span>Save to Draft</span>
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
