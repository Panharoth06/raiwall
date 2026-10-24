<script setup lang="ts">
import { computed } from 'vue';
import type { ConditionGroup, VisualCondition, MatchTarget, MatchOperator } from '@/types/acl';
import {
  TARGET_OPTIONS,
  OPERATOR_OPTIONS,
  getTargetConfig,
} from './aclRuleTranspiler';
import CountrySelector from './CountrySelector.vue';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Plus, Trash2, Globe2 } from 'lucide-vue-next';

const props = defineProps<{
  group: ConditionGroup;
  groupIndex: number;
  canRemoveGroup: boolean;
}>();

const emit = defineEmits<{
  (e: 'add-condition'): void;
  (e: 'remove-condition', conditionId: string): void;
  (e: 'remove-group'): void;
}>();

const handleTargetChange = (c: VisualCondition, newTarget: MatchTarget) => {
  c.target = newTarget;
  const cfg = getTargetConfig(newTarget);
  if (!cfg.supportedOperators.includes(c.operator)) {
    c.operator = cfg.supportedOperators[0];
  }
  if (!cfg.requiresKey) {
    c.key = undefined;
  } else if (!c.key) {
    c.key = '';
  }
  if (c.operator === 'in_geo' || c.operator === 'not_in_geo' || newTarget === 'country') {
    if (!c.content || c.content.includes('.') || c.content.includes('/')) {
      c.content = '';
    }
  }
};

const handleOperatorChange = (c: VisualCondition, newOp: MatchOperator) => {
  c.operator = newOp;
  if ((newOp === 'in_geo' || newOp === 'not_in_geo') && (c.content.includes('.') || c.content.includes('/'))) {
    c.content = '';
  }
};

const getOperatorsForTarget = (target: MatchTarget) => {
  const cfg = getTargetConfig(target);
  return OPERATOR_OPTIONS.filter((op) => cfg.supportedOperators.includes(op.value));
};

const isGeoOperator = (c: VisualCondition) => {
  return c.operator === 'in_geo' || c.operator === 'not_in_geo' || c.target === 'country';
};
</script>

<template>
  <div class="rounded-lg border border-border bg-card/60 p-3.5 space-y-3">
    <!-- List of AND conditions with visual diagram connector -->
    <div class="relative" :class="{ 'pl-7 sm:pl-8': group.conditions.length > 1 }">
      <!-- AND Diagram Connector Rail (rendered when 2+ conditions in group) -->
      <div
        v-if="group.conditions.length > 1"
        class="absolute left-2.5 top-5 bottom-5 w-3 border-l-2 border-primary/40 rounded-l-sm pointer-events-none flex items-center"
      >
        <span
          class="absolute -left-3.5 px-1 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider bg-card text-primary border border-primary/50 shadow-none select-none"
        >
          AND
        </span>
      </div>

      <div class="space-y-3">
        <div
          v-for="(c, cIdx) in group.conditions"
          :key="c.id"
          class="relative grid grid-cols-12 gap-2.5 items-end"
        >
          <!-- Horizontal connector branch into each row -->
          <div
            v-if="group.conditions.length > 1"
            class="hidden sm:block absolute -left-5 top-1/2 -translate-y-1/2 w-4 border-t-2 border-primary/40 pointer-events-none"
          />

          <!-- Match Target -->
        <div
          class="col-span-12 min-w-0"
          :class="getTargetConfig(c.target).requiresKey ? 'sm:col-span-3' : 'sm:col-span-3'"
        >
          <label class="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
            Match Target *
          </label>
          <Select
            :model-value="c.target"
            @update:model-value="(val) => handleTargetChange(c, val as MatchTarget)"
          >
            <SelectTrigger class="h-9 w-full bg-background text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem
                v-for="opt in TARGET_OPTIONS"
                :key="opt.value"
                :value="opt.value"
              >
                {{ opt.label }}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        <!-- Optional Key input for Header / Query / Cookie -->
        <div
          v-if="getTargetConfig(c.target).requiresKey"
          class="col-span-12 sm:col-span-2 min-w-0"
        >
          <label class="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
            Name / Key *
          </label>
          <Input
            v-model="c.key"
            placeholder="e.g. Authorization"
            class="h-9 text-xs font-mono"
          />
        </div>

        <!-- Operator -->
        <div
          class="col-span-12 min-w-0"
          :class="getTargetConfig(c.target).requiresKey ? 'sm:col-span-3' : 'sm:col-span-3'"
        >
          <label class="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
            Operator *
          </label>
          <Select
            :model-value="c.operator"
            @update:model-value="(val) => handleOperatorChange(c, val as MatchOperator)"
          >
            <SelectTrigger class="h-9 w-full bg-background text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem
                v-for="op in getOperatorsForTarget(c.target)"
                :key="op.value"
                :value="op.value"
              >
                <div class="flex items-center gap-1.5">
                  <Globe2 v-if="op.value === 'in_geo' || op.value === 'not_in_geo'" class="w-3 h-3 text-primary shrink-0" />
                  <span>{{ op.label }}</span>
                </div>
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        <!-- Content (CountrySelector or Input) -->
        <div
          class="col-span-10 min-w-0"
          :class="getTargetConfig(c.target).requiresKey ? 'sm:col-span-3' : 'sm:col-span-5'"
        >
          <label class="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
            Content *
          </label>
          <CountrySelector
            v-if="isGeoOperator(c)"
            v-model="c.content"
          />
          <Input
            v-else
            v-model="c.content"
            :placeholder="getTargetConfig(c.target).placeholder"
            class="h-9 text-xs font-mono"
          />
        </div>

        <!-- Trash delete button -->
        <div class="col-span-2 sm:col-span-1 flex items-end justify-center pb-0.5">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            :disabled="group.conditions.length <= 1"
            @click="emit('remove-condition', c.id)"
            class="h-9 w-9 text-muted-foreground hover:text-threat transition-colors"
            title="Delete this condition"
          >
            <Trash2 class="w-4 h-4" />
          </Button>
        </div>
      </div>
    </div>
  </div>

  <!-- Bottom buttons inside the group -->
    <div class="flex items-center justify-between pt-2 border-t border-border/60">
      <Button
        type="button"
        variant="outline"
        size="sm"
        @click="emit('add-condition')"
        class="h-8 text-xs gap-1.5 border-dashed border-primary/40 text-primary hover:bg-primary/10"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>ADD AN AND CONDITION</span>
      </Button>

      <Button
        v-if="canRemoveGroup"
        type="button"
        variant="ghost"
        size="sm"
        @click="emit('remove-group')"
        class="h-8 text-xs text-muted-foreground hover:text-threat"
      >
        REMOVE THIS CONDITION GROUP
      </Button>
    </div>
  </div>
</template>
