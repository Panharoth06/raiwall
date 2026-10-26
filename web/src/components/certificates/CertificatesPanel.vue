<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { CertificatePayload, ManagedCertificate } from '@/api/client'
import { api } from '@/api/client'
import { useConfigStore } from '@/stores/config'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/components/ui/empty-state'
import { ConfirmDialog } from '@/components/ui/dialog'
import { Lock, Plus, RefreshCw, ShieldCheck } from 'lucide-vue-next'
import CertificateTable from './CertificateTable.vue'
import CertificateDialog from './CertificateDialog.vue'

const configStore = useConfigStore()

const dialogOpen = ref(false)
const editing = ref<ManagedCertificate | null>(null)
const submitting = ref(false)
const dialogError = ref<string | null>(null)

const busyId = ref<string | null>(null)
const loading = ref(false)
const notice = ref<string | null>(null)
const failure = ref<string | null>(null)

const deleteTarget = ref<ManagedCertificate | null>(null)
const showDeleteConfirm = ref(false)

const load = async () => {
  loading.value = true
  failure.value = null
  try {
    await configStore.loadCertificates()
  } catch (err: unknown) {
    failure.value = err instanceof Error ? err.message : 'Failed to load certificates'
  } finally {
    loading.value = false
  }
}

onMounted(load)

const openCreate = () => {
  editing.value = null
  dialogError.value = null
  dialogOpen.value = true
}

const openEdit = (cert: ManagedCertificate) => {
  editing.value = cert
  dialogError.value = null
  dialogOpen.value = true
}

const handleSave = async (payload: CertificatePayload) => {
  submitting.value = true
  dialogError.value = null
  try {
    if (editing.value) {
      await configStore.updateCertificate(editing.value.id, {
        name: payload.name,
        domains: payload.domains,
        auto_renew: payload.auto_renew,
      })
      notice.value = `Updated ${payload.name}`
    } else {
      await configStore.createCertificate(payload)
      notice.value =
        payload.source === 'acme'
          ? `Queued ACME issuance for ${payload.domains.join(', ')} — apply to request the certificate.`
          : `Created ${payload.name}`
    }
    dialogOpen.value = false
  } catch (err: unknown) {
    dialogError.value = err instanceof Error ? err.message : 'Failed to save certificate'
  } finally {
    submitting.value = false
  }
}

const handleRenew = async (cert: ManagedCertificate) => {
  busyId.value = cert.id
  notice.value = null
  failure.value = null
  try {
    await configStore.renewCertificate(cert.id)
    notice.value = `Renewed ${cert.name}`
  } catch (err: unknown) {
    failure.value = err instanceof Error ? err.message : `Failed to renew ${cert.name}`
  } finally {
    busyId.value = null
  }
}

const handleDownload = async (cert: ManagedCertificate) => {
  failure.value = null
  try {
    const blob = await api.downloadCertificate(cert.id)
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${cert.name.replace(/[^a-z0-9._-]+/gi, '_')}.pem`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    notice.value = `Downloaded ${cert.name}`
  } catch (err: unknown) {
    failure.value = err instanceof Error ? err.message : `Failed to download ${cert.name}`
  }
}

const requestDelete = (cert: ManagedCertificate) => {
  deleteTarget.value = cert
  showDeleteConfirm.value = true
}

const confirmDelete = async () => {
  const cert = deleteTarget.value
  showDeleteConfirm.value = false
  deleteTarget.value = null
  if (!cert) return
  failure.value = null
  try {
    await configStore.deleteCertificate(cert.id)
    notice.value = `Deleted ${cert.name}`
  } catch (err: unknown) {
    failure.value = err instanceof Error ? err.message : `Failed to delete ${cert.name}`
  }
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h3 class="text-sm font-semibold text-foreground flex items-center gap-2">
          <Lock class="w-4 h-4 text-primary" />
          <span>TLS Certificates</span>
        </h3>
        <p class="text-xs text-muted-foreground mt-1 leading-relaxed">
          Managed material for the <span class="font-mono">:8443</span> listener. Keys are
          AES-256-GCM encrypted at rest; renewal runs inside the 30-day expiry window.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <Button
          variant="outline"
          class="h-8 px-3 text-xs gap-1.5"
          :disabled="loading"
          @click="load"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': loading }" />
          <span>Refresh</span>
        </Button>
        <Button class="h-8 px-3 text-xs gap-1.5" @click="openCreate">
          <Plus class="w-3.5 h-3.5" />
          <span>Add Certificate</span>
        </Button>
      </div>
    </div>

    <div
      v-if="failure"
      class="flex items-start gap-2 rounded-md border border-threat/30 bg-threat/5 px-3 py-2"
      role="alert"
    >
      <span class="text-xs text-threat">{{ failure }}</span>
    </div>
    <div
      v-if="notice"
      class="flex items-center gap-2 rounded-md border border-success/30 bg-success/5 px-3 py-2"
    >
      <ShieldCheck class="w-3.5 h-3.5 text-success" />
      <span class="text-xs text-success">{{ notice }}</span>
    </div>

    <div class="border border-border rounded-lg overflow-hidden">
      <div v-if="loading && configStore.certificates.length === 0" class="p-6 space-y-2">
        <div v-for="row in 3" :key="row" class="h-8 rounded bg-muted animate-pulse" />
      </div>

      <EmptyState
        v-else-if="configStore.certificates.length === 0"
        :icon="Lock"
        title="No certificates managed yet"
        description="Generate a self-signed certificate for internal apps, upload a PEM pair, or queue ACME issuance for public hostnames."
        class="py-10"
      >
        <Button class="gap-1.5" @click="openCreate">
          <Plus class="w-4 h-4" />
          <span>Add Certificate</span>
        </Button>
      </EmptyState>

      <CertificateTable
        v-else
        :certificates="configStore.certificates"
        :busy-id="busyId"
        @edit="openEdit"
        @renew="handleRenew"
        @download="handleDownload"
        @delete="requestDelete"
      />
    </div>

    <div class="flex items-center gap-2">
      <Badge variant="outline" class="text-xs font-mono">
        {{ configStore.certificates.length }} managed
      </Badge>
      <Badge
        v-if="configStore.certificates.some((c) => c.status === 'expiring' || c.status === 'expired')"
        variant="warning"
        class="text-xs font-mono"
      >
        {{ configStore.certificates.filter((c) => c.status === 'expiring' || c.status === 'expired').length }} need attention
      </Badge>
    </div>

    <CertificateDialog
      :open="dialogOpen"
      :certificate="editing"
      :submitting="submitting"
      :error="dialogError"
      @close="dialogOpen = false"
      @save="handleSave"
    />

    <ConfirmDialog
      v-model:open="showDeleteConfirm"
      title="Delete Certificate"
      :description="`Delete ${deleteTarget?.name || 'this certificate'}? Sites that reference it must be updated first.`"
      confirm-text="Delete Certificate"
      variant="destructive"
      @confirm="confirmDelete"
      @cancel="showDeleteConfirm = false"
    />
  </div>
</template>
