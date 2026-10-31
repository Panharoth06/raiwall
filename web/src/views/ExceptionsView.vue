<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute } from '@/router'
import { useConfigStore } from '@/stores/config'
import type { ExceptionRule } from '@/api/client'
import ExceptionTestModal from '@/components/ExceptionTestModal.vue'
import DetectionHeroBanner from '@/components/detection/DetectionHeroBanner.vue'
import { useHeroBanner } from '@/components/detection/useHeroBanner'
import { Button } from '@/components/ui/button'
import AdminOnly from '@/components/auth/AdminOnly.vue'
import { Input } from '@/components/ui/input'
import { ConfirmDialog } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { TablePagination } from '@/components/ui/table-pagination'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select'
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { HelpCircle, Plus, Shield, ShieldCheck, ShieldOff, Trash2, Play } from 'lucide-vue-next'

const route = useRoute()
const configStore = useConfigStore()

const { showHero, toggleHero, dismissHero } = useHeroBanner('detection-exceptions')
const showAddModal = ref(false)
const addError = ref<string | null>(null)
const newHost = ref('*')
const newPath = ref('')
const newMethod = ref('ALL')
const newLocation = ref('query')
const newParamName = ref('')
const newReason = ref('')
const newRuleId = ref('ALL')

const testModalOpen = ref(false)
const selectedRuleForTest = ref<ExceptionRule | null>(null)
const deleteRuleId = ref<string | null>(null)
const showDeleteConfirm = ref(false)

const page = ref(1)
const pageSize = ref(20)

const paginatedExceptions = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return configStore.exceptions.slice(start, start + pageSize.value)
})

const openAddModal = () => {
  newHost.value = '*'
  newPath.value = ''
  newMethod.value = 'ALL'
  newLocation.value = 'query'
  newParamName.value = ''
  newReason.value = ''
  newRuleId.value = 'ALL'
  addError.value = null
  showAddModal.value = true
}

const checkQueryAndOpen = () => {
  const q = route?.value?.query
  if (q && (q.path || q.param_name || q.rule_id)) {
    newHost.value = (q.host as string) || '*'
    newPath.value = (q.path as string) || ''
    newMethod.value = (q.method as string) || 'ALL'
    newLocation.value = (q.location as string)?.toLowerCase() || 'query'
    newParamName.value = (q.param_name as string) || ''
    newReason.value = (q.reason as string) || 'Bypass false-positive via Forensic triage'
    newRuleId.value = (q.rule_id as string) || 'ALL'
    addError.value = null
    showAddModal.value = true
  }
}

onMounted(() => {
  checkQueryAndOpen()
})

watch(() => route?.value?.query, () => {
  checkQueryAndOpen()
})

const handleSaveException = async () => {
  if (!newPath.value || !newParamName.value) {
    addError.value = 'Path and Parameter Name are required'
    return
  }

  await configStore.createException({
    host: newHost.value || '*',
    path: newPath.value,
    method: newMethod.value,
    location: newLocation.value,
    param_name: newParamName.value,
    reason: newReason.value || 'False-positive suppression',
    rule_id: newRuleId.value || 'ALL',
  })

  showAddModal.value = false
}

const openTestSimulator = (rule: ExceptionRule) => {
  selectedRuleForTest.value = rule
  testModalOpen.value = true
}

const confirmDelete = (id: string) => {
  deleteRuleId.value = id
  showDeleteConfirm.value = true
}

const executeDelete = async () => {
  if (deleteRuleId.value) {
    await configStore.deleteException(deleteRuleId.value)
    deleteRuleId.value = null
  }
  showDeleteConfirm.value = false
}
</script>

<template>
  <div class="space-y-4 font-sans">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-border shrink-0">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <Shield class="w-5 h-5 text-primary" />
          <span>False-Positive Exceptions</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Safely whitelist specific parameters, webhooks, or paths that contain legitimate symbols without lowering security globally.
        </p>
      </div>

      <div class="flex items-center gap-2 shrink-0">
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :data-testid="'hero-toggle-exceptions'"
          @click="toggleHero"
        >
          <HelpCircle class="w-3.5 h-3.5 text-primary" />
          <span>{{ showHero ? 'Hide Guide' : 'Explain feature' }}</span>
        </Button>
        <AdminOnly>
          <Button
            @click="openAddModal"
            size="sm"
            class="h-8 text-xs gap-1.5"
          >
            <Plus class="w-4 h-4" />
            <span>Add Exception Rule</span>
          </Button>
        </AdminOnly>
      </div>
    </div>

    <!-- Prominent Hero Section with Low-Opacity Background Icon -->
    <DetectionHeroBanner
      storage-key="detection-exceptions"
      title="False-Positive Suppression & Parameter Exceptions"
      badge="GRANULAR BYPASSES"
      description="When legitimate traffic (such as webhook callbacks, Base64 payment tokens, or markdown editor inputs) contains characters that trigger WAF alerts, do not disable the WAF. Instead, create an exception rule to selectively bypass inspection for that specific Host, Path, Method, Location, and Parameter Name."
      :icon="ShieldOff"
      :highlights="[
        { label: 'Surgical Precision', text: 'Whitelist exact parameters (query, body, header, cookie) without opening the route.' },
        { label: 'Highest Priority Layer', text: 'Exceptions evaluate before all AST parsers and CRS anomaly checks.' },
        { label: 'Forensic Linkage', text: '1-click exception generation directly from blocked attack logs under Attacks.' },
      ]"
      v-model:open="showHero"
      @dismiss="dismissHero"
    />

    <!-- Exceptions Table Container -->
    <div class="flex-1 min-h-0 bg-card border border-border rounded-lg overflow-auto">
      <EmptyState
        v-if="configStore.exceptions.length === 0"
        :icon="ShieldCheck"
        title="No exception rules defined"
        description="Suppress false-positives without disabling the WAF globally."
        class="py-12"
      >
        <AdminOnly>
          <Button
            @click="openAddModal"
            class="gap-1.5"
          >
            <Plus class="w-4 h-4" />
            <span>Add First Exception</span>
          </Button>
        </AdminOnly>
      </EmptyState>

      <Table v-else container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="text-xs uppercase font-semibold">Host / Path</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Method</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Location</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Parameter Name</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Suppressed Threat</TableHead>
            <TableHead class="text-xs uppercase font-semibold">Reason</TableHead>
            <TableHead class="text-right text-xs uppercase font-semibold">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="rule in paginatedExceptions" :key="rule.id">
            <TableCell>
              <span class="text-foreground font-medium block font-mono text-sm">{{ rule.path }}</span>
              <span class="text-xs text-muted-foreground font-mono">{{ rule.host || '*' }}</span>
            </TableCell>
            <TableCell class="font-mono text-xs">
              <span class="px-2 py-0.5 bg-primary/10 border border-primary/30 rounded text-primary">
                {{ rule.method }}
              </span>
            </TableCell>
            <TableCell>
              <span class="capitalize text-foreground font-mono text-xs">{{ rule.location }}</span>
            </TableCell>
            <TableCell class="font-mono text-success font-semibold text-xs">
              {{ rule.param_name }}
            </TableCell>
            <TableCell class="font-mono text-muted-foreground text-xs">
              {{ rule.rule_id || 'ALL' }}
            </TableCell>
            <TableCell class="text-muted-foreground truncate max-w-xs text-xs">
              {{ rule.reason }}
            </TableCell>
            <TableCell class="text-right space-x-1">
              <TooltipProvider :delay-duration="150">
                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="ghost"
                      size="icon"
                      data-testid="exception-test"
                      class="h-7 w-7 text-muted-foreground hover:text-foreground"
                      @click="openTestSimulator(rule)"
                    >
                      <Play class="w-3.5 h-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <p class="text-xs">Test with simulator</p>
                  </TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="ghost"
                      size="icon"
                      data-testid="exception-delete"
                      class="h-7 w-7 text-muted-foreground hover:text-threat"
                      @click="confirmDelete(rule.id)"
                    >
                      <Trash2 class="w-3.5 h-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <p class="text-xs">Delete exception</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <TablePagination
        :page="page"
        :page-size="pageSize"
        :total="configStore.exceptions.length"
        :page-size-options="[10, 20, 50, 100]"
        item-label="exceptions"
        @update:page="(p) => page = p"
        @update:page-size="(s) => { pageSize = s; page = 1; }"
      />
    </div>

    <!-- Add Exception Modal -->
    <Dialog :open="showAddModal" @update:open="showAddModal = $event">
      <DialogContent class="max-w-md bg-card border-border">
        <DialogHeader>
          <div class="flex items-center space-x-2">
            <Shield class="w-5 h-5 text-primary" />
            <DialogTitle class="text-base font-semibold text-foreground">Add Rule Exception</DialogTitle>
          </div>
        </DialogHeader>

        <div class="space-y-4 py-2">
          <div v-if="addError" class="p-3 bg-threat/10 border border-threat/30 rounded-lg text-threat text-xs">
            {{ addError }}
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Target Host (* for all)</label>
            <Input v-model="newHost" placeholder="e.g. api.example.com or *" />
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Request Path</label>
            <Input v-model="newPath" placeholder="e.g. /checkout/payment" />
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">HTTP Method</label>
              <Select v-model="newMethod">
                <SelectTrigger class="w-full h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent class="bg-popover text-popover-foreground border-border">
                  <SelectItem value="ALL">ALL</SelectItem>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Parameter Location</label>
              <Select v-model="newLocation">
                <SelectTrigger class="w-full h-9 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent class="bg-popover text-popover-foreground border-border">
                  <SelectItem value="query">Query Parameter</SelectItem>
                  <SelectItem value="header">Request Header</SelectItem>
                  <SelectItem value="cookie">Cookie</SelectItem>
                  <SelectItem value="body">Request Body</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Parameter Name</label>
            <Input v-model="newParamName" placeholder="e.g. signature or token" />
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Target Rule (or ALL)</label>
            <Input v-model="newRuleId" placeholder="e.g. SEMANTIC_SQLI or ALL" />
          </div>

          <div>
            <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Suppression Reason</label>
            <Input v-model="newReason" placeholder="e.g. Base64 encoded payload in webhook" />
          </div>
        </div>

        <DialogFooter class="flex gap-2 justify-end pt-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            @click="showAddModal = false"
          >
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            @click="handleSaveException"
          >
            Add Exception
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Exception Simulation Test Modal -->
    <ExceptionTestModal
      v-if="selectedRuleForTest"
      :open="testModalOpen"
      :rule="selectedRuleForTest"
      @close="testModalOpen = false"
    />

    <!-- Delete Confirmation Modal -->
    <ConfirmDialog
      v-model:open="showDeleteConfirm"
      title="Delete Rule Exception"
      description="Are you sure you want to delete this exception rule? The WAF will immediately resume inspecting this parameter."
      confirm-text="Delete Exception"
      variant="destructive"
      @confirm="executeDelete"
      @cancel="showDeleteConfirm = false"
    />
  </div>
</template>
