<script setup lang="ts">
import { ref } from 'vue';
import { api } from '@/api/client';
import { Button } from '@/components/ui/button';
import { CheckCircle2, AlertCircle } from 'lucide-vue-next';

const props = defineProps<{
  modelValue: string;
}>();

const emit = defineEmits<{
  (e: 'update:modelValue', val: string): void;
}>();

const validating = ref(false);
const validationResult = ref<{ valid: boolean; error?: string } | null>(null);

const validateSyntax = async () => {
  const expr = props.modelValue.trim();
  if (!expr) {
    validationResult.value = { valid: false, error: 'Expression cannot be empty' };
    return;
  }
  validating.value = true;
  try {
    const res = await api.dryRunACL({
      expression: expr,
      request: { ClientIP: '127.0.0.1', Path: '/test', Method: 'GET' },
    });
    validationResult.value = res;
  } catch (err: unknown) {
    validationResult.value = {
      valid: false,
      error: err instanceof Error ? err.message : 'Syntax compilation error',
    };
  } finally {
    validating.value = false;
  }
};
</script>

<template>
  <div class="space-y-2">
    <div class="flex items-center justify-between">
      <label class="text-xs font-mono text-muted-foreground">
        Boolean Expression (expr-lang)
      </label>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        :disabled="validating"
        @click="validateSyntax"
        class="h-6 text-xs px-2 text-primary hover:bg-primary/10"
      >
        {{ validating ? 'Verifying...' : 'Verify Syntax' }}
      </Button>
    </div>

    <textarea
      :value="modelValue"
      @input="emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
      rows="4"
      class="w-full px-3 py-2 bg-card border border-input rounded-md text-foreground placeholder:text-muted-foreground font-mono text-xs focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring transition-colors"
      placeholder='in_cidr(client_ip, "192.168.0.0/16") && path == "/admin"'
    />

    <!-- Syntax feedback banner -->
    <div v-if="validationResult" class="text-xs flex items-center space-x-2">
      <div v-if="validationResult.valid" class="text-success flex items-center space-x-1.5">
        <CheckCircle2 class="w-4 h-4 text-success shrink-0" />
        <span>Expression verified cleanly (sub-15ns bytecode compatible)</span>
      </div>
      <div v-else class="text-threat flex items-center space-x-1.5 font-mono text-xs">
        <AlertCircle class="w-4 h-4 text-threat shrink-0" />
        <span>{{ validationResult.error }}</span>
      </div>
    </div>
  </div>
</template>
