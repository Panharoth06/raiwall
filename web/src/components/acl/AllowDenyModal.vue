<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import type { ACLRule } from '@/api/client';
import type { ConditionGroup, VisualRuleForm } from '@/types/acl';
import { groupsToExpr, exprToGroups } from './aclRuleTranspiler';
import ConditionGroupBuilder from './ConditionGroupBuilder.vue';
import AdvancedExprEditor from './AdvancedExprEditor.vue';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { ShieldCheck, Ban, Plus, Code2, Save } from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
  rule?: ACLRule | null;
  defaultAction?: 'allow' | 'block';
  existingPriorities?: number[];
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', rule: Partial<ACLRule>): void;
}>();

const form = ref<VisualRuleForm>({
  action: 'allow',
  name: '',
  insertPosition: 'first',
  priority: 100,
  groups: [],
  continueInspection: false,
  enabled: true,
  rawExpr: '',
  isAdvancedMode: false,
});

const createDefaultGroup = (gIdx: number = 1): ConditionGroup => ({
  id: `group-${Date.now()}-${gIdx}`,
  conditions: [
    {
      id: `cond-${Date.now()}-1`,
      target: 'source_ip',
      operator: 'equals',
      content: '',
    },
  ],
});

watch(
  () => props.open,
  (isOpen) => {
    if (!isOpen) return;
    if (props.rule) {
      const parsedGroups = exprToGroups(props.rule.expression);
      form.value = {
        id: props.rule.id,
        action: props.rule.action === 'allow' ? 'allow' : 'block',
        name: props.rule.name,
        insertPosition: 'first',
        priority: props.rule.priority,
        groups: parsedGroups || [createDefaultGroup(1)],
        continueInspection: !!props.rule.continue_inspection,
        enabled: props.rule.enabled !== false,
        rawExpr: props.rule.expression,
        isAdvancedMode: !parsedGroups,
      };
    } else {
      form.value = {
        action: props.defaultAction || 'allow',
        name: '',
        insertPosition: 'first',
        priority: 100,
        groups: [createDefaultGroup(1)],
        continueInspection: false,
        enabled: true,
        rawExpr: 'client_ip == "192.168.10.10"',
        isAdvancedMode: false,
      };
    }
  },
  { immediate: true }
);

const compiledExpression = computed(() =>
  form.value.isAdvancedMode ? form.value.rawExpr : groupsToExpr(form.value.groups)
);

const addOrGroup = () => {
  form.value.groups.push(createDefaultGroup(form.value.groups.length + 1));
};

const removeGroup = (gIdx: number) => {
  if (form.value.groups.length > 1) form.value.groups.splice(gIdx, 1);
};

const addConditionToGroup = (group: ConditionGroup) => {
  group.conditions.push({
    id: `cond-${Date.now()}-${group.conditions.length + 1}`,
    target: 'source_ip',
    operator: 'equals',
    content: '',
  });
};

const removeConditionFromGroup = (group: ConditionGroup, cId: string) => {
  if (group.conditions.length > 1) {
    group.conditions = group.conditions.filter((c) => c.id !== cId);
  }
};

const toggleAdvancedMode = () => {
  if (!form.value.isAdvancedMode) {
    form.value.rawExpr = compiledExpression.value;
  } else {
    const parsed = exprToGroups(form.value.rawExpr);
    if (parsed) form.value.groups = parsed;
  }
  form.value.isAdvancedMode = !form.value.isAdvancedMode;
};

const calculatePriority = (): number => {
  if (props.rule) return props.rule.priority;
  const existing = props.existingPriorities || [];
  if (existing.length === 0) return 100;
  const min = Math.min(...existing);
  const max = Math.max(...existing);
  return form.value.insertPosition === 'first' ? Math.max(1, min - 10) : max + 10;
};

const handleSubmit = () => {
  if (!form.value.name.trim()) {
    alert('Please provide a rule name.');
    return;
  }

  const expr = compiledExpression.value.trim();
  if (!expr) {
    alert('Please configure at least one condition or expression.');
    return;
  }

  emit('save', {
    id: form.value.id,
    name: form.value.name.trim(),
    action: form.value.action,
    expression: expr,
    priority: calculatePriority(),
    enabled: form.value.enabled,
    continue_inspection: form.value.continueInspection,
  });
  emit('close');
};
</script>

<template>
  <Dialog :open="open" @update:open="(val) => !val && $emit('close')">
    <DialogContent class="max-w-4xl w-full max-h-[88vh] flex flex-col p-6 overflow-hidden">
      <DialogHeader class="shrink-0 border-b border-border pb-3">
        <DialogTitle class="text-base font-semibold text-foreground">
          {{ rule ? 'Edit Rule' : 'Add rules' }}
        </DialogTitle>
      </DialogHeader>

      <!-- Scrollable Form Body -->
      <div class="flex-1 overflow-y-auto overflow-x-hidden py-4 space-y-4 pr-1">
        <!-- 1. Allow vs Deny Rule Top Selector -->
        <div class="grid grid-cols-2 gap-3">
          <button
            type="button"
            @click="form.action = 'allow'"
            :class="[
              'flex items-center justify-center gap-2.5 p-3 rounded-lg border text-xs font-semibold transition-all cursor-pointer',
              form.action === 'allow'
                ? 'border-primary bg-primary/10 text-primary ring-1 ring-primary/40'
                : 'border-border bg-card/40 text-muted-foreground hover:bg-muted/40 hover:text-foreground'
            ]"
          >
            <div
              class="w-4 h-4 rounded-full border flex items-center justify-center shrink-0"
              :class="form.action === 'allow' ? 'border-primary' : 'border-muted-foreground'"
            >
              <div v-if="form.action === 'allow'" class="w-2 h-2 rounded-full bg-primary" />
            </div>
            <ShieldCheck class="w-4 h-4 text-primary" />
            <span>Allow</span>
          </button>
          <button
            type="button"
            @click="form.action = 'block'"
            :class="[
              'flex items-center justify-center gap-2.5 p-3 rounded-lg border text-xs font-semibold transition-all cursor-pointer',
              form.action === 'block'
                ? 'border-threat bg-threat/10 text-threat ring-1 ring-threat/40'
                : 'border-border bg-card/40 text-muted-foreground hover:bg-muted/40 hover:text-foreground'
            ]"
          >
            <div
              class="w-4 h-4 rounded-full border flex items-center justify-center shrink-0"
              :class="form.action === 'block' ? 'border-threat' : 'border-muted-foreground'"
            >
              <div v-if="form.action === 'block'" class="w-2 h-2 rounded-full bg-threat" />
            </div>
            <Ban class="w-4 h-4 text-threat" />
            <span>Deny Rule</span>
          </button>
        </div>

        <!-- 2. Name & Insert Position -->
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div class="sm:col-span-2">
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
              Name *
            </label>
            <Input
              v-model="form.name"
              placeholder="e.g. Allow Office Network"
              class="h-9 text-xs"
            />
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
              Insert Position
            </label>
            <Select v-model="form.insertPosition">
              <SelectTrigger class="h-9 w-full bg-background text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="first">First</SelectItem>
                <SelectItem value="last">Last</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <!-- Mode Toggle & Expression Preview -->
        <div class="flex items-center justify-between pt-1">
          <span class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Match Conditions
          </span>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            @click="toggleAdvancedMode"
            class="h-7 text-xs text-muted-foreground hover:text-foreground gap-1.5"
          >
            <Code2 class="w-3.5 h-3.5" />
            <span>{{ form.isAdvancedMode ? 'Visual Builder' : 'Advanced expr Mode' }}</span>
          </Button>
        </div>

        <AdvancedExprEditor
          v-if="form.isAdvancedMode"
          v-model="form.rawExpr"
        />

        <div v-else class="space-y-3">
          <template v-for="(grp, gIdx) in form.groups" :key="grp.id">
            <!-- Diagram Connector Between OR Groups -->
            <div v-if="gIdx > 0" class="flex items-center justify-center my-2 relative select-none">
              <div class="absolute inset-0 flex items-center">
                <div class="w-full border-t border-border"></div>
              </div>
              <div class="relative flex items-center gap-1.5 px-3 py-1 rounded-full bg-card border border-warning/50 text-warning text-[10px] font-mono font-bold tracking-wider uppercase shadow-none">
                <span>OR</span>
              </div>
            </div>

            <ConditionGroupBuilder
              :group="grp"
              :group-index="gIdx"
              :can-remove-group="form.groups.length > 1"
              @add-condition="addConditionToGroup(grp)"
              @remove-condition="(cId) => removeConditionFromGroup(grp, cId)"
              @remove-group="removeGroup(gIdx)"
            />
          </template>

          <Button
            type="button"
            variant="outline"
            @click="addOrGroup"
            class="w-full h-9 text-xs border-dashed border-primary/50 text-primary hover:bg-primary/10 gap-1.5"
          >
            <Plus class="w-3.5 h-3.5" />
            <span>ADD AN OR CONDITION</span>
          </Button>
        </div>

        <!-- 5. Options Checkboxes -->
        <div class="pt-2 space-y-2.5 border-t border-border">
          <div class="flex items-center space-x-2">
            <input
              type="checkbox"
              id="continue-inspection"
              v-model="form.continueInspection"
              class="rounded border-border text-primary focus:ring-primary accent-primary w-4 h-4 cursor-pointer"
            />
            <label for="continue-inspection" class="text-xs text-foreground cursor-pointer select-none">
              Continue to detect and log attack requests even when {{ form.action === 'allow' ? 'whitelisting' : 'denying' }}.
            </label>
          </div>

          <div class="flex items-center space-x-2">
            <input
              type="checkbox"
              id="rule-enabled"
              v-model="form.enabled"
              class="rounded border-border text-primary focus:ring-primary accent-primary w-4 h-4 cursor-pointer"
            />
            <label for="rule-enabled" class="text-xs text-foreground font-medium cursor-pointer select-none">
              Enabled
            </label>
          </div>
        </div>
      </div>

      <!-- Footer Buttons -->
      <DialogFooter class="shrink-0 border-t border-border pt-3 flex items-center justify-end gap-2.5">
        <Button
          type="button"
          variant="ghost"
          @click="$emit('close')"
          class="h-9 px-4 text-xs font-medium text-muted-foreground hover:text-foreground"
        >
          CANCEL
        </Button>
        <Button
          type="button"
          @click="handleSubmit"
          class="h-9 px-5 text-xs font-semibold gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
        >
          <Save class="w-3.5 h-3.5" />
          <span>SUBMIT</span>
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
