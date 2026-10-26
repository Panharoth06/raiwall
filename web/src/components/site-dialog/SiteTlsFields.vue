<script setup lang="ts">
import type { ManagedCertificate } from '@/api/client';
import { Button } from '@/components/ui/button';
import { NumberInput } from '@/components/ui/number-input';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Plus, Trash2 } from 'lucide-vue-next';
import type { PortEntry, SslMode } from './useSiteForm';

const ports = defineModel<PortEntry[]>('ports', { required: true });
const sslMode = defineModel<SslMode>('sslMode', { required: true });
const certificateId = defineModel<string>('certificateId', { required: true });

defineProps<{
  certificates: ManagedCertificate[];
  usableCertificates: ManagedCertificate[];
  unusableCertificates: ManagedCertificate[];
  hasHttpsPort: boolean;
}>();

const emit = defineEmits<{
  (e: 'add-port'): void;
  (e: 'remove-port', index: number): void;
}>();

const toggleScheme = (index: number, scheme: 'http' | 'https') => {
  ports.value = ports.value.map((entry, idx) => (idx === index ? { ...entry, scheme } : entry));
};
</script>

<template>
  <div class="space-y-4">
    <div class="space-y-2">
      <label class="text-xs font-semibold text-foreground flex items-center gap-1">
        <span>Listening port</span>
        <span class="text-threat">*</span>
      </label>
      <p class="text-xs text-muted-foreground leading-relaxed">
        Declarative metadata for validation and reporting — the gateway binds shared listeners on
        <span class="font-mono">:8080</span> (HTTP) and <span class="font-mono">:8443</span> (HTTPS).
      </p>

      <div v-for="(entry, idx) in ports" :key="entry.id" class="flex items-center gap-2">
        <div class="w-32">
          <NumberInput v-model="entry.port" :min="1" :max="65535" placeholder="80" class="h-9" />
        </div>

        <div class="inline-flex rounded-md border border-input p-0.5 bg-muted/40 shrink-0">
          <button
            type="button"
            class="px-3 py-1 text-xs rounded font-medium transition-colors cursor-pointer"
            :class="
              entry.scheme === 'http'
                ? 'bg-primary text-primary-foreground font-semibold'
                : 'text-muted-foreground hover:text-foreground'
            "
            @click="toggleScheme(idx, 'http')"
          >
            HTTP
          </button>
          <button
            type="button"
            class="px-3 py-1 text-xs rounded font-medium transition-colors cursor-pointer"
            :class="
              entry.scheme === 'https'
                ? 'bg-primary text-primary-foreground font-semibold'
                : 'text-muted-foreground hover:text-foreground'
            "
            @click="toggleScheme(idx, 'https')"
          >
            HTTPS
          </button>
        </div>

        <button
          type="button"
          :disabled="ports.length <= 1"
          class="p-2 text-muted-foreground hover:text-threat disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer ml-auto"
          title="Remove port"
          @click="emit('remove-port', idx)"
        >
          <Trash2 class="w-4 h-4" />
        </button>
      </div>

      <Button
        type="button"
        variant="outline"
        class="w-full h-8 border-dashed border-primary/40 text-primary hover:bg-primary/5 text-xs font-semibold uppercase tracking-wider gap-1.5 shadow-none"
        @click="emit('add-port')"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>ADD LISTENING PORT</span>
      </Button>
    </div>

    <div v-if="hasHttpsPort" class="space-y-1.5">
      <label class="text-xs font-semibold text-foreground">TLS certificate</label>
      <Select v-model="sslMode">
        <SelectTrigger class="w-full h-9 text-xs" aria-label="TLS mode">
          <SelectValue placeholder="Select TLS mode" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="auto">Auto — ACME for public DNS, self-signed for internal</SelectItem>
          <SelectItem value="manual">Manual — pick a managed certificate</SelectItem>
        </SelectContent>
      </Select>

      <Select v-if="sslMode === 'manual'" v-model="certificateId">
        <SelectTrigger class="w-full h-9 text-xs" aria-label="Managed certificate">
          <SelectValue placeholder="Select a certificate" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem v-for="cert in usableCertificates" :key="cert.id" :value="cert.id">
            {{ cert.name }} — {{ cert.domains.join(', ') }} ({{ cert.status }})
          </SelectItem>
          <SelectItem v-for="cert in unusableCertificates" :key="cert.id" :value="cert.id" disabled>
            {{ cert.name }} — does not cover every hostname
          </SelectItem>
        </SelectContent>
      </Select>

      <p v-if="sslMode === 'auto'" class="text-xs text-muted-foreground leading-relaxed">
        Public hostnames are issued through ACME; private or internal names get a managed
        self-signed certificate. No certificate is needed up front.
      </p>
      <p v-else-if="certificates.length === 0" class="text-xs text-warning leading-relaxed">
        No managed certificates yet. Create one under Settings → Certificates first.
      </p>
      <p v-else-if="usableCertificates.length === 0" class="text-xs text-warning leading-relaxed">
        No certificate covers every hostname of this site. Adjust the hostnames or issue a new
        certificate.
      </p>
    </div>

    <p v-else class="text-xs text-muted-foreground leading-relaxed">
      No HTTPS listener configured — this site serves plain HTTP only.
    </p>
  </div>
</template>
