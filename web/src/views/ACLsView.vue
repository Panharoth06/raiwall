<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { ACLRule } from '@/api/client';
import ACLExprEditor from '@/components/ACLExprEditor.vue';
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
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight flex items-center space-x-2.5">
          <FileCode class="w-6 h-6 text-emerald-400" />
          <span>Bytecode ACL Rules (expr-lang)</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">
          High-performance compiled boolean rules evaluated in sub-15ns before deep payload inspection.
        </p>
      </div>

      <button
        @click="openAddRule"
        class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-2"
      >
        <Plus class="w-4 h-4" />
        <span>New ACL Rule</span>
      </button>
    </div>

    <!-- ACLs Table -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      <div v-if="configStore.acls.length === 0" class="p-12 text-center">
        <FileCode class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 class="text-sm font-semibold text-slate-300">No custom ACL rules configured</h3>
        <p class="text-xs text-slate-500 mt-1 mb-4">
          Add boolean access control rules to block, allow, or redirect traffic based on client IPs, headers, or paths.
        </p>
        <button
          @click="openAddRule"
          class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors"
        >
          Add First ACL Rule
        </button>
      </div>

      <table v-else class="w-full text-left text-xs text-slate-300">
        <thead class="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
          <tr>
            <th class="py-3 px-4">Priority</th>
            <th class="py-3 px-4">Rule Name</th>
            <th class="py-3 px-4">Boolean Expression</th>
            <th class="py-3 px-4">Action</th>
            <th class="py-3 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/60">
          <tr v-for="rule in configStore.acls" :key="rule.id" class="hover:bg-slate-800/40 transition-colors">
            <td class="py-3.5 px-4 font-mono text-slate-400 font-semibold">
              #{{ rule.priority }}
            </td>
            <td class="py-3.5 px-4 font-medium text-white">
              {{ rule.name }}
            </td>
            <td class="py-3.5 px-4 font-mono text-emerald-400 text-[11px] truncate max-w-md">
              {{ rule.expression }}
            </td>
            <td class="py-3.5 px-4">
              <span
                v-if="rule.action === 'block'"
                class="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30"
              >
                <Ban class="w-3 h-3" />
                <span>Block (403)</span>
              </span>
              <span
                v-else-if="rule.action === 'allow'"
                class="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              >
                <CheckCircle class="w-3 h-3" />
                <span>Allow</span>
              </span>
              <span
                v-else
                class="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30"
              >
                <ArrowRightCircle class="w-3 h-3" />
                <span>Redirect</span>
              </span>
            </td>
            <td class="py-3.5 px-4 text-right space-x-2">
              <button
                @click="openEditRule(rule)"
                class="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors"
                title="Edit rule"
              >
                <Edit2 class="w-4 h-4" />
              </button>
              <button
                @click="handleDelete(rule.id)"
                class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                title="Delete rule"
              >
                <Trash2 class="w-4 h-4" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
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
