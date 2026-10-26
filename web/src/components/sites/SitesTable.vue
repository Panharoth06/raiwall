<script setup lang="ts">
import type { ManagedCertificate, Site } from '@/api/client'
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
import {
  Bot,
  CornerDownRight,
  Edit2,
  Eye,
  FileText,
  Lock,
  LockOpen,
  Network,
  PowerOff,
  ShieldCheck,
  Trash2,
} from 'lucide-vue-next'

const props = defineProps<{
  sites: Site[]
  certificates: ManagedCertificate[]
}>()

const emit = defineEmits<{
  (e: 'edit', site: Site): void
  (e: 'delete', siteId: string): void
  (e: 'bot-protect', site: Site): void
}>()

const routeLabels: Record<string, string> = {
  proxy: 'Reverse Proxy',
  static: 'Static Files',
  redirect: 'Redirect',
}

const balanceLabels: Record<string, string> = {
  round_robin: 'round-robin',
  least_conn: 'least-conn',
  ip_hash: 'ip-hash',
  primary_backup: 'primary-backup',
}

const sslLabels: Record<string, string> = {
  none: 'HTTP only',
  auto: 'Auto TLS',
  manual: 'Manual TLS',
}

const routeDetail = (site: Site) => {
  if (site.routing_type === 'static') return site.document_root || 'No document root'
  if (site.routing_type === 'redirect') {
    return `${site.redirect_status || 302} → ${site.redirect_url || 'unset'}`
  }
  const targets = site.upstreams?.length || 0
  const balance = site.load_balancing || 'round_robin'
  return `${targets} target${targets === 1 ? '' : 's'} · ${balanceLabels[balance] || balance}`
}

const certificateName = (id?: string) => {
  if (!id) return ''
  return props.certificates.find((cert) => cert.id === id)?.name || id
}
</script>

<template>
  <Table container-class="overflow-visible">
    <TableHeader>
      <TableRow>
        <TableHead class="text-xs uppercase font-semibold">Application Site</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Hostnames</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Route</TableHead>
        <TableHead class="text-xs uppercase font-semibold">TLS</TableHead>
        <TableHead class="text-xs uppercase font-semibold">Mode</TableHead>
        <TableHead class="text-right text-xs uppercase font-semibold">Actions</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="site in props.sites" :key="site.id">
        <TableCell class="max-w-[220px]">
          <div class="font-medium text-foreground text-sm truncate">{{ site.name }}</div>
          <div v-if="site.description" class="text-xs text-muted-foreground truncate">
            {{ site.description }}
          </div>
        </TableCell>
        <TableCell>
          <div class="flex flex-wrap gap-1.5">
            <span
              v-for="host in site.hostnames"
              :key="host"
              class="px-2 py-0.5 bg-muted border border-border rounded text-xs text-foreground font-mono"
            >
              {{ host }}
            </span>
          </div>
        </TableCell>
        <TableCell class="max-w-[260px]">
          <div class="flex items-center gap-1.5 text-xs text-foreground">
            <FileText v-if="site.routing_type === 'static'" class="w-3.5 h-3.5 text-muted-foreground" />
            <CornerDownRight
              v-else-if="site.routing_type === 'redirect'"
              class="w-3.5 h-3.5 text-muted-foreground"
            />
            <Network v-else class="w-3.5 h-3.5 text-muted-foreground" />
            <span class="font-medium">{{ routeLabels[site.routing_type] || site.routing_type }}</span>
          </div>
          <div class="text-xs text-muted-foreground font-mono truncate" :title="routeDetail(site)">
            {{ routeDetail(site) }}
          </div>
        </TableCell>
        <TableCell>
          <div
            class="flex items-center gap-1.5 text-xs"
            :class="site.ssl_mode === 'none' ? 'text-muted-foreground' : 'text-foreground'"
          >
            <LockOpen v-if="site.ssl_mode === 'none'" class="w-3.5 h-3.5" />
            <Lock v-else class="w-3.5 h-3.5" />
            <span>{{ sslLabels[site.ssl_mode] || site.ssl_mode }}</span>
          </div>
          <div
            v-if="site.ssl_mode === 'manual' && site.certificate_id"
            class="text-xs text-muted-foreground font-mono truncate"
            :title="site.certificate_id"
          >
            {{ certificateName(site.certificate_id) }}
          </div>
          <div v-else-if="site.ssl_mode === 'auto'" class="text-xs text-muted-foreground font-mono">
            {{ (site.ports || []).filter((p) => p.scheme === 'https').length }} https port(s)
          </div>
        </TableCell>
        <TableCell>
          <Badge v-if="site.mode === 'defense'" variant="success" class="gap-1 font-mono uppercase text-xs">
            <ShieldCheck class="w-3.5 h-3.5 text-success" />
            <span>Defense</span>
          </Badge>
          <Badge v-else-if="site.mode === 'audit'" variant="info" class="gap-1 font-mono uppercase text-xs">
            <Eye class="w-3.5 h-3.5 text-info" />
            <span>Audit</span>
          </Badge>
          <Badge v-else variant="threat" class="gap-1 font-mono uppercase text-xs">
            <PowerOff class="w-3.5 h-3.5 text-threat" />
            <span>Offline (503)</span>
          </Badge>
        </TableCell>
        <TableCell class="text-right space-x-1">
          <TooltipProvider :delay-duration="150">
            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  data-testid="site-bot-protect"
                  class="h-7 w-7 text-muted-foreground hover:text-foreground"
                  @click="emit('bot-protect', site)"
                >
                  <Bot class="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Bot Protection</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 text-muted-foreground hover:text-foreground"
                  @click="emit('edit', site)"
                >
                  <Edit2 class="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Edit Site</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 text-muted-foreground hover:text-threat"
                  @click="emit('delete', site.id)"
                >
                  <Trash2 class="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                <p class="text-xs">Delete Site</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
