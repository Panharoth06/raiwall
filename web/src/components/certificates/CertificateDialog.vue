<script setup lang="ts">
import { ref, watch } from 'vue'
import type { CertificatePayload, CertificateSource, ManagedCertificate } from '@/api/client'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select'
import { X } from 'lucide-vue-next'

const props = withDefaults(
  defineProps<{
    open: boolean
    certificate?: ManagedCertificate | null
    submitting?: boolean
    error?: string | null
  }>(),
  { certificate: null, submitting: false, error: null }
)

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'save', payload: CertificatePayload): void
}>()

const name = ref('')
const domains = ref<string[]>([])
const domainInput = ref('')
const source = ref<CertificateSource>('self_signed')
const certPem = ref('')
const keyPem = ref('')
const autoRenew = ref(true)
const localError = ref('')

const reset = () => {
  name.value = ''
  domains.value = []
  domainInput.value = ''
  source.value = 'self_signed'
  certPem.value = ''
  keyPem.value = ''
  autoRenew.value = true
  localError.value = ''
}

watch(
  () => props.certificate,
  (cert) => {
    if (!cert) {
      reset()
      return
    }
    name.value = cert.name
    domains.value = [...cert.domains]
    domainInput.value = ''
    source.value = cert.source
    certPem.value = ''
    keyPem.value = ''
    autoRenew.value = cert.auto_renew
    localError.value = ''
  },
  { immediate: true }
)

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen && !props.certificate) reset()
  }
)

const addDomain = () => {
  const raw = domainInput.value.trim()
  if (!raw) return
  for (const part of raw.split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    if (!domains.value.includes(part)) domains.value.push(part)
  }
  domainInput.value = ''
}

const removeDomain = (idx: number) => {
  domains.value.splice(idx, 1)
}

const submit = () => {
  addDomain()
  localError.value = ''
  if (domains.value.length === 0) {
    localError.value = 'Add at least one domain name.'
    return
  }
  if (source.value === 'upload' && !props.certificate) {
    if (!certPem.value.trim() || !keyPem.value.trim()) {
      localError.value = 'Upload requires both the certificate chain and the private key.'
      return
    }
  }

  const payload: CertificatePayload = {
    name: name.value.trim() || domains.value[0],
    domains: [...domains.value],
    source: source.value,
    auto_renew: autoRenew.value,
  }
  if (source.value === 'upload' && !props.certificate) {
    payload.cert_pem = certPem.value.trim()
    payload.key_pem = keyPem.value.trim()
  }
  emit('save', payload)
}

const isEdit = () => Boolean(props.certificate)
</script>

<template>
  <Dialog :open="open" @update:open="(value) => !value && emit('close')">
    <DialogContent
      class="max-w-lg max-h-[90vh] flex flex-col p-6 bg-card text-card-foreground font-sans rounded-xl border border-border shadow-none overflow-hidden"
    >
      <div class="flex items-center justify-between pb-3 border-b border-border shrink-0">
        <div>
          <DialogTitle class="text-base font-semibold text-foreground">
            {{ isEdit() ? 'Edit Certificate' : 'Add Certificate' }}
          </DialogTitle>
          <DialogDescription class="text-xs text-muted-foreground mt-0.5">
            Private keys are encrypted at rest and never returned by the API.
          </DialogDescription>
        </div>
        <button
          type="button"
          class="text-muted-foreground hover:text-foreground p-1 rounded-md transition-colors cursor-pointer"
          aria-label="Close"
          @click="emit('close')"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <div class="py-4 overflow-y-auto space-y-4 flex-1 pr-1">
        <div class="space-y-1.5">
          <label class="text-xs font-semibold text-foreground">Name</label>
          <Input v-model="name" placeholder="Primary wildcard" class="h-9 text-xs" />
        </div>

        <div class="space-y-1.5">
          <label class="text-xs font-semibold text-foreground flex items-center gap-1">
            <span>Domains</span>
            <span class="text-threat">*</span>
          </label>
          <div
            class="flex flex-wrap items-center gap-1.5 p-2 rounded-md border border-input bg-card min-h-[40px] focus-within:border-primary focus-within:ring-1 focus-within:ring-ring transition-colors"
          >
            <span
              v-for="(domain, idx) in domains"
              :key="domain"
              class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-muted text-foreground text-xs font-mono border border-border"
            >
              <span>{{ domain }}</span>
              <button
                type="button"
                class="text-muted-foreground hover:text-threat transition-colors cursor-pointer"
                title="Remove domain"
                @click="removeDomain(idx)"
              >
                <X class="w-3 h-3" />
              </button>
            </span>
            <input
              v-model="domainInput"
              type="text"
              placeholder="app.example.com, *.example.com"
              class="flex-1 bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none min-w-[160px]"
              @keydown.enter.prevent="addDomain"
              @keydown.comma.prevent="addDomain"
              @blur="addDomain"
            />
          </div>
          <p class="text-xs text-muted-foreground">
            Wildcards must use a single label, e.g. <span class="font-mono">*.example.com</span>.
          </p>
        </div>

        <div class="space-y-1.5">
          <label class="text-xs font-semibold text-foreground">Source</label>
          <Select v-model="source" :disabled="isEdit()">
            <SelectTrigger class="w-full h-9 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="self_signed">Self-signed — generated on the gateway</SelectItem>
              <SelectItem value="upload">Upload — bring your own PEM</SelectItem>
              <SelectItem value="acme">ACME — Let's Encrypt production</SelectItem>
            </SelectContent>
          </Select>
          <p v-if="isEdit()" class="text-xs text-muted-foreground">
            Source and key material are immutable. Use renew or upload a new certificate.
          </p>
          <p v-else-if="source === 'acme'" class="text-xs text-muted-foreground leading-relaxed">
            Issued on the next apply. The hostname must resolve publicly and port 80 must be
            reachable for the HTTP-01 challenge.
          </p>
        </div>

        <template v-if="source === 'upload' && !isEdit()">
          <div class="space-y-1.5">
            <label class="text-xs font-semibold text-foreground flex items-center gap-1">
              <span>Certificate chain (PEM)</span>
              <span class="text-threat">*</span>
            </label>
            <Textarea v-model="certPem" :rows="5" placeholder="-----BEGIN CERTIFICATE-----" />
          </div>
          <div class="space-y-1.5">
            <label class="text-xs font-semibold text-foreground flex items-center gap-1">
              <span>Private key (PEM)</span>
              <span class="text-threat">*</span>
            </label>
            <Textarea v-model="keyPem" :rows="5" placeholder="-----BEGIN PRIVATE KEY-----" />
            <p class="text-xs text-muted-foreground">
              The key must match the leaf certificate. It is AES-256-GCM encrypted before storage.
            </p>
          </div>
        </template>

        <div v-if="source !== 'upload'" class="flex items-center justify-between rounded-md border border-border px-3 py-2">
          <div>
            <p class="text-xs font-semibold text-foreground">Auto-renew</p>
            <p class="text-xs text-muted-foreground">
              Regenerate or re-issue before the 14-day expiry window.
            </p>
          </div>
          <Switch v-model:checked="autoRenew" aria-label="Auto-renew certificate" />
        </div>

        <p
          v-if="localError || error"
          class="text-xs text-threat border border-threat/30 bg-threat/5 rounded-md px-3 py-2"
          role="alert"
        >
          {{ localError || error }}
        </p>
      </div>

      <div class="flex items-center justify-end gap-3 pt-3 border-t border-border shrink-0">
        <Button
          type="button"
          variant="ghost"
          class="h-9 px-5 text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground"
          :disabled="submitting"
          @click="emit('close')"
        >
          CANCEL
        </Button>
        <Button
          type="button"
          class="h-9 px-6 text-xs font-semibold uppercase tracking-wider"
          :disabled="submitting"
          @click="submit"
        >
          {{ submitting ? 'SAVING…' : 'SUBMIT' }}
        </Button>
      </div>
    </DialogContent>
  </Dialog>
</template>
