<script setup lang="ts">
import { ref, watch } from 'vue';
import { api, type ACLRule } from '@/api/client';
import { X, CheckCircle2, AlertCircle, Save, Code } from 'lucide-vue-next';

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
</script>

<template>
  <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
    <div class="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl flex flex-col">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div class="flex items-center space-x-2.5">
          <Code class="w-5 h-5 text-emerald-400" />
          <h2 class="text-base font-semibold text-white">
            {{ rule ? 'Edit ACL Rule' : 'New ACL Bytecode Rule' }}
          </h2>
        </div>
        <button @click="$emit('close')" class="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Body -->
      <div class="p-6 space-y-4">
        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Rule Name</label>
          <input
            v-model="formName"
            type="text"
            placeholder="e.g. block_internal_admin"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Verdict Action</label>
            <select
              v-model="formAction"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            >
              <option value="block">Block (HTTP 403)</option>
              <option value="allow">Allow (Bypass remaining checks)</option>
              <option value="redirect">Redirect (HTTP 302)</option>
            </select>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Priority</label>
            <input
              v-model.number="formPriority"
              type="number"
              class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div v-if="formAction === 'redirect'">
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Redirect URL</label>
          <input
            v-model="formRedirectUrl"
            type="text"
            placeholder="https://example.com/login"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-sm focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div>
          <div class="flex items-center justify-between mb-1">
            <label class="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Boolean Expression (expr-lang)
            </label>
            <button
              type="button"
              @click="validateSyntax"
              :disabled="validating"
              class="text-xs text-emerald-400 hover:text-emerald-300 font-medium"
            >
              {{ validating ? 'Validating...' : 'Check Syntax' }}
            </button>
          </div>
          <textarea
            v-model="formExpr"
            rows="3"
            placeholder="ClientIP in '192.168.0.0/16' && Method == 'POST'"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
          ></textarea>
        </div>

        <!-- Syntax Check Feedback -->
        <div v-if="validationResult" class="p-3 rounded-lg text-xs flex items-center space-x-2" :class="validationResult.valid ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border border-rose-500/30 text-rose-400'">
          <component :is="validationResult.valid ? CheckCircle2 : AlertCircle" class="w-4 h-4 flex-shrink-0" />
          <span>{{ validationResult.valid ? 'Syntax valid (compiles in < 15 ns)' : validationResult.error }}</span>
        </div>
      </div>

      <!-- Footer -->
      <div class="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3">
        <button
          type="button"
          @click="$emit('close')"
          class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          @click="handleSave"
          class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5"
        >
          <Save class="w-3.5 h-3.5" />
          <span>Save Rule</span>
        </button>
      </div>
    </div>
  </div>
</template>
