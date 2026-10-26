<script setup lang="ts">
import type { ManagedCertificate } from '@/api/client'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { Download, RefreshCw, Trash2, ShieldCheck, ShieldAlert, Edit2 } from 'lucide-vue-next'

const props = defineProps<{
  certificates: ManagedCertificate[]
  busyId?: string | null
}>()

const emit = defineEmits<{
  (e: 'edit', certificate: ManagedCertificate): void
  (e: 'renew', certificate: ManagedCertificate): void
  (e: 'download', certificate: ManagedCertificate): void
  (e: 'delete', certificate: ManagedCertificate): void
}>()

const statusVariant = (status: ManagedCertificate['status']) => {
  switch (status) {
    case 'valid':
      return 'success' as const
    case 'expiring':
      return 'warning' as const
    case 'expired':
      return 'threat' as const
    default:
      return 'info' as const
  }
}

const sourceLabel = (source: ManagedCertificate['source']) => {
  switch (source) {
    case 'self_signed':
      return 'Self-signed'
    case 'acme':
      return 'ACME'
    default:
      return 'Uploaded'
  }
}

const formatDate = (value?: string) => {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toISOString().slice(0, 10)
}

const daysLeft = (value?: string) => {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return Math.round((date.getTime() - Date.now()) / 86_400_000)
}
</script>

<template>
  <Table container-class="overflow-visible">
    <TableHeader>
      <TableRow>
        <TableHead class="text-xs uppercase font-semibold">Certificate</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Domains</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Source</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Validity</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Status</TableHead>
        <TableHead class="text-right text-xs uppercase font-semibold">Actions</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="cert in props.certificates" :key="cert.id">
        <TableCell class="max-w-[220px]">
          <div class="text-sm font-medium text-foreground truncate">{{ cert.name }}</div>
          <div class="text-xs text-muted-foreground font-mono truncate" :title="cert.fingerprint_sha256">
            {{ cert.fingerprint_sha256 ? cert.fingerprint_sha256.slice(0, 16) + '…' : 'no material yet' }}
          </div>
        </TableCell>
        <TableCell class="max-w-[240px]">
          <div class="flex flex-wrap gap-1">
            <span
              v-for="domain in cert.domains"
              :key="domain"
              class="px-1.5 py-0.5 rounded bg-muted border border-border text-xs font-mono text-foreground"
            >
              {{ domain }}
            </span>
          </div>
        </TableCell>
        <TableCell class="text-xs text-muted-foreground">
          {{ sourceLabel(cert.source) }}
        </TableCell>
        <TableCell class="text-xs text-muted-foreground font-mono tabular-nums">
          <div>{{ formatDate(cert.not_before) }} → {{ formatDate(cert.not_after) }}</div>
          <div v-if="daysLeft(cert.not_after) !== null" class="text-xs">
            {{ daysLeft(cert.not_after) }} day(s) remaining
          </div>
          <div v-if="cert.auto_renew" class="text-xs text-success">auto-renew on</div>
        </TableCell>
        <TableCell>
          <Badge :variant="statusVariant(cert.status)" class="gap-1 text-xs font-mono uppercase">
            <ShieldCheck v-if="cert.status === 'valid'" class="w-3.5 h-3.5" />
            <ShieldAlert v-else class="w-3.5 h-3.5" />
            <span>{{ cert.status }}</span>
          </Badge>
          <p v-if="cert.last_error" class="text-xs text-threat mt-1 max-w-[200px] truncate" :title="cert.last_error">
            {{ cert.last_error }}
          </p>
        </TableCell>
        <TableCell class="text-right">
          <TooltipProvider :delay-duration="150">
            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 text-muted-foreground hover:text-foreground"
                  :aria-label="`Edit ${cert.name}`"
                  @click="emit('edit', cert)"
                >
                  <Edit2 class="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Edit certificate</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip v-if="cert.source !== 'upload'">
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 text-muted-foreground hover:text-foreground"
                  :disabled="props.busyId === cert.id"
                  :aria-label="`Renew ${cert.name}`"
                  @click="emit('renew', cert)"
                >
                  <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': props.busyId === cert.id }" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Renew certificate</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip v-if="cert.cert_pem">
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 text-muted-foreground hover:text-foreground"
                  :aria-label="`Download ${cert.name}`"
                  @click="emit('download', cert)"
                >
                  <Download class="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Download PEM</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 text-muted-foreground hover:text-threat"
                  :aria-label="`Delete ${cert.name}`"
                  @click="emit('delete', cert)"
                >
                  <Trash2 class="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Delete certificate</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
