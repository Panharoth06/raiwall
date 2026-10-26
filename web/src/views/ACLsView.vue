<script setup lang="ts">
import { ref, computed } from 'vue'
import { useConfigStore } from '@/stores/config'
import type { ACLRule } from '@/api/client'
import AllowDenyTable from '@/components/acl/AllowDenyTable.vue'
import AllowDenyModal from '@/components/acl/AllowDenyModal.vue'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/ui/dialog'
import { Plus, ShieldCheck } from 'lucide-vue-next'

type AllowDenyTab = 'whitelist' | 'blacklist'

const configStore = useConfigStore()
const activeTab = ref<AllowDenyTab>('whitelist')

const editorOpen = ref(false)
const editingRule = ref<ACLRule | null>(null)
const deleteRuleId = ref<string | null>(null)
const showDeleteConfirm = ref(false)

const whitelistRules = computed(() =>
  configStore.acls
    .filter((r) => r.action === 'allow')
    .sort((a, b) => a.priority - b.priority)
)

const blacklistRules = computed(() =>
  configStore.acls
    .filter((r) => r.action === 'block' || r.action === 'redirect')
    .sort((a, b) => a.priority - b.priority)
)

const currentRules = computed(() =>
  activeTab.value === 'whitelist' ? whitelistRules.value : blacklistRules.value
)

const existingPriorities = computed(() =>
  configStore.acls.map((r) => r.priority)
)

const openAddRule = () => {
  editingRule.value = null
  editorOpen.value = true
}

const openEditRule = (rule: ACLRule) => {
  editingRule.value = rule
  editorOpen.value = true
}

const handleSaveRule = async (ruleData: Partial<ACLRule>) => {
  if (ruleData.id) {
    await configStore.updateACL(ruleData.id, ruleData)
  } else {
    await configStore.createACL(ruleData)
  }
}

const confirmDelete = (id: string) => {
  deleteRuleId.value = id
  showDeleteConfirm.value = true
}

const executeDelete = async () => {
  if (deleteRuleId.value) {
    await configStore.deleteACL(deleteRuleId.value)
    deleteRuleId.value = null
  }
  showDeleteConfirm.value = false
}

const handleToggleStatus = async (rule: ACLRule) => {
  await configStore.updateACL(rule.id, {
    enabled: !rule.enabled,
  })
}

const handleMoveUp = async (rule: ACLRule, index: number) => {
  if (index <= 0) return
  const list = currentRules.value
  const prevRule = list[index - 1]
  const temp = rule.priority
  const newPriority = prevRule.priority > 0 ? prevRule.priority : 1
  const prevNewPriority = temp > newPriority ? temp : newPriority + 10

  await configStore.updateACL(rule.id, { priority: newPriority - 1 })
  await configStore.updateACL(prevRule.id, { priority: prevNewPriority })
}

const handleMoveDown = async (rule: ACLRule, index: number) => {
  const list = currentRules.value
  if (index >= list.length - 1) return
  const nextRule = list[index + 1]
  const nextPriority = nextRule.priority
  await configStore.updateACL(rule.id, { priority: nextPriority + 1 })
}
</script>

<template>
  <div class="h-full flex flex-col space-y-6 p-6 bg-card text-card-foreground rounded-xl border border-border font-sans overflow-hidden">
    <!-- Standard View Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-border shrink-0">
      <div class="min-w-0">
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <ShieldCheck class="w-5 h-5 text-primary" />
          <span>Allow & Deny Rules</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Configure multi-condition whitelist bypasses and blacklist block rules evaluated in sub-15ns bytecode.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <Badge variant="outline" class="font-mono text-xs uppercase">
          Bytecode Engine · expr-lang · CIDR
        </Badge>
        <Button
          @click="openAddRule"
          class="gap-1.5"
        >
          <Plus class="w-4 h-4" />
          <span>ADD RULES</span>
        </Button>
      </div>
    </div>

    <!-- Whitelist / Blacklist Selector Tabs -->
    <div class="flex items-center gap-2 shrink-0 border-b border-border pb-3">
      <Button
        type="button"
        variant="ghost"
        size="sm"
        @click="activeTab = 'whitelist'"
        :class="[
          'px-4 py-1.5 text-xs font-semibold rounded-md uppercase tracking-wider transition-all cursor-pointer',
          activeTab === 'whitelist'
            ? 'bg-primary/15 text-primary border border-primary/40'
            : 'text-muted-foreground hover:text-foreground hover:bg-muted/50 border border-transparent'
        ]"
      >
        <span>WHITELIST</span>
        <span class="ml-1.5 font-mono text-xs opacity-80 tabular-nums">
          ({{ whitelistRules.length }})
        </span>
      </Button>

      <Button
        type="button"
        variant="ghost"
        size="sm"
        @click="activeTab = 'blacklist'"
        :class="[
          'px-4 py-1.5 text-xs font-semibold rounded-md uppercase tracking-wider transition-all cursor-pointer',
          activeTab === 'blacklist'
            ? 'bg-threat/15 text-threat border border-threat/40'
            : 'text-muted-foreground hover:text-foreground hover:bg-muted/50 border border-transparent'
        ]"
      >
        <span>BLACKLIST</span>
        <span class="ml-1.5 font-mono text-xs opacity-80 tabular-nums">
          ({{ blacklistRules.length }})
        </span>
      </Button>
    </div>

    <!-- Active Table View -->
    <div class="flex-1 min-h-0 overflow-hidden">
      <AllowDenyTable
        :rules="currentRules"
        :active-tab="activeTab === 'whitelist' ? 'allow' : 'block'"
        @edit="openEditRule"
        @delete="confirmDelete"
        @toggle-status="handleToggleStatus"
        @move-up="handleMoveUp"
        @move-down="handleMoveDown"
        @add-rule="openAddRule"
      />
    </div>

    <!-- SafeLine-style Add/Edit Modal Dialog -->
    <AllowDenyModal
      :open="editorOpen"
      :rule="editingRule"
      :default-action="activeTab === 'whitelist' ? 'allow' : 'block'"
      :existing-priorities="existingPriorities"
      @close="editorOpen = false"
      @save="handleSaveRule"
    />

    <!-- Delete Confirmation Modal -->
    <ConfirmDialog
      v-model:open="showDeleteConfirm"
      title="Delete Rule"
      description="Are you sure you want to delete this ACL rule? Evaluation will immediately bypass this rule."
      confirm-text="Delete Rule"
      variant="destructive"
      @confirm="executeDelete"
      @cancel="showDeleteConfirm = false"
    />
  </div>
</template>
