<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { ACLRule } from '@/api/client';
import ACLExprEditor from '@/components/ACLExprEditor.vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Plus, FileCode, Edit2, Trash2, Ban, CheckCircle, ArrowRightCircle } from 'lucide-vue-next';

const configStore = useConfigStore();

const editorOpen = ref(false);
const editingRule = ref<ACLRule | null>(null);

const openAddRule = () => {
  editingRule.value = null;
  editorOpen.value = true;
};

const openEditRule = (rule: ACLRule) => {
  editingRule.value = rule;
  editorOpen.value = true;
};

const handleSaveRule = async (ruleData: Partial<ACLRule>) => {
  if (ruleData.id) {
    await configStore.updateACL(ruleData.id, ruleData);
  } else {
    await configStore.createACL(ruleData);
  }
};

const handleDelete = async (id: string) => {
  if (confirm('Delete this ACL rule?')) {
    await configStore.deleteACL(id);
  }
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-[#0d0f14] text-zinc-100 rounded-xl border border-zinc-800 shadow-2xl font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-white flex items-center gap-2">
          <FileCode class="w-4 h-4 text-slate-400" />
          <span>Bytecode ACL Rules (expr-lang)</span>
        </h1>
        <p class="text-[11px] text-zinc-400 mt-0.5">
          High-performance compiled boolean rules evaluated in sub-15ns before deep inspection.
        </p>
      </div>

      <Button
        @click="openAddRule"
        class="gap-1.5"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>New ACL Rule</span>
      </Button>
    </div>

    <!-- ACLs Table Container -->
    <div class="flex-1 min-h-0 bg-[#12151c] border border-zinc-800 rounded-lg overflow-y-auto">
      <div v-if="configStore.acls.length === 0" class="p-12 text-center">
        <FileCode class="w-10 h-10 text-slate-400 mx-auto mb-3" />
        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-300">No custom ACL rules configured</h3>
        <p class="text-[11px] text-slate-400 mt-1 mb-4">
          Add boolean access control rules to block, allow, or redirect traffic based on client IPs, headers, or paths.
        </p>
        <Button
          @click="openAddRule"
          class="gap-1.5"
        >
          <Plus class="w-3.5 h-3.5" />
          <span>Add First ACL Rule</span>
        </Button>
      </div>

      <Table v-else>
        <TableHeader class="sticky top-0 z-10 bg-[#14171d]">
          <TableRow>
            <TableHead class="font-mono text-[11px]">Priority</TableHead>
            <TableHead class="font-mono text-[11px]">Rule Name</TableHead>
            <TableHead class="font-mono text-[11px]">Boolean Expression</TableHead>
            <TableHead class="font-mono text-[11px]">Action</TableHead>
            <TableHead class="font-mono text-[11px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="rule in configStore.acls" :key="rule.id">
            <TableCell class="font-mono text-slate-400 font-semibold text-[11px]">
              #{{ rule.priority }}
            </TableCell>
            <TableCell class="font-medium text-white">
              {{ rule.name }}
            </TableCell>
            <TableCell class="font-mono text-[#38BDF8] text-[11px] truncate max-w-md">
              {{ rule.expression }}
            </TableCell>
            <TableCell>
              <Badge
                v-if="rule.action === 'block'"
                variant="rose"
                class="gap-1 font-mono uppercase"
              >
                <Ban class="w-3 h-3 text-slate-400" />
                <span>Block (403)</span>
              </Badge>
              <Badge
                v-else-if="rule.action === 'allow'"
                variant="emerald"
                class="gap-1 font-mono uppercase"
              >
                <CheckCircle class="w-3 h-3 text-slate-400" />
                <span>Allow</span>
              </Badge>
              <Badge
                v-else
                variant="amber"
                class="gap-1 font-mono uppercase"
              >
                <ArrowRightCircle class="w-3 h-3 text-slate-400" />
                <span>Redirect</span>
              </Badge>
            </TableCell>
            <TableCell class="text-right space-x-1">
              <Button
                variant="ghost"
                size="icon"
                @click="openEditRule(rule)"
                title="Edit rule"
                class="h-7 w-7 text-slate-400 hover:text-white"
              >
                <Edit2 class="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                @click="handleDelete(rule.id)"
                title="Delete rule"
                class="h-7 w-7 text-slate-400 hover:text-red-400"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- ACL Editor Modal -->
    <ACLExprEditor
      :open="editorOpen"
      :rule="editingRule"
      @close="editorOpen = false"
      @save="handleSaveRule"
    />
  </div>
</template>
