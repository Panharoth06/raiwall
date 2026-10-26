<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import type { Site, Upstream } from '@/api/client';
import {
  Dialog,
  DialogContent,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { NumberInput } from '@/components/ui/number-input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Plus, Trash2, X, ChevronDown, Info } from 'lucide-vue-next';

export interface ListeningPort {
  id: string;
  port: number;
  scheme: 'http' | 'https';
}

export interface UpstreamEntry {
  id: string;
  dial: string;
  weight: number;
}

const props = defineProps<{
  open: boolean;
  site?: Site | null;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', site: Partial<Site>): void;
}>();

// SafeLine Form State
const domains = ref<string[]>(['*']);
const domainInput = ref('');

const ports = ref<ListeningPort[]>([
  { id: '1', port: 80, scheme: 'http' },
  { id: '2', port: 443, scheme: 'https' },
]);

const sslCert = ref('auto');
const routingType = ref<'proxy' | 'static' | 'redirect'>('proxy');

const upstreams = ref<UpstreamEntry[]>([
  { id: '1', dial: 'http://127.0.0.1:8080', weight: 1 },
]);

const loadBalancing = ref<'round_robin' | 'least_conn' | 'ip_hash' | 'primary_backup'>('round_robin');
const appName = ref('');
const appDescription = ref('');

// Advanced Settings (Operational Mode & Status Codes)
const advancedOpen = ref(false);
const formMode = ref<'defense' | 'audit' | 'offline'>('defense');
const formBlockCode = ref(403);
const formOfflineCode = ref(503);

const hasHttpsPort = computed(() => ports.value.some((p) => p.scheme === 'https'));

watch(
  () => props.site,
  (val) => {
    if (val) {
      appName.value = val.name || '';
      domains.value = val.hostnames && val.hostnames.length > 0 ? [...val.hostnames] : ['*'];
      formMode.value = val.mode || 'defense';
      formBlockCode.value = val.block_status_code || 403;
      formOfflineCode.value = val.offline_status_code || 503;

      if (val.upstreams && val.upstreams.length > 0) {
        upstreams.value = val.upstreams.map((u, i) => ({
          id: String(i + 1),
          dial: u.dial.includes('://') ? u.dial : `http://${u.dial}`,
          weight: u.weight || 1,
        }));
      } else {
        upstreams.value = [{ id: '1', dial: 'http://127.0.0.1:8080', weight: 1 }];
      }
    } else {
      // Default initial state for new application
      appName.value = '';
      appDescription.value = '';
      domains.value = ['*'];
      domainInput.value = '';
      ports.value = [
        { id: '1', port: 80, scheme: 'http' },
        { id: '2', port: 443, scheme: 'https' },
      ];
      sslCert.value = 'auto';
      routingType.value = 'proxy';
      upstreams.value = [{ id: '1', dial: 'http://127.0.0.1:8080', weight: 1 }];
      loadBalancing.value = 'round_robin';
      formMode.value = 'defense';
      formBlockCode.value = 403;
      formOfflineCode.value = 503;
      advancedOpen.value = false;
    }
  },
  { immediate: true }
);

// Domain Tag Management
const addDomain = () => {
  const raw = domainInput.value.trim();
  if (!raw) return;

  const parts = raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    if (!domains.value.includes(part)) {
      domains.value.push(part);
    }
  }
  domainInput.value = '';
};

const removeDomain = (idx: number) => {
  domains.value.splice(idx, 1);
  if (domains.value.length === 0) {
    domains.value = ['*'];
  }
};

// Listening Ports Management
const addPort = () => {
  const nextPort = ports.value.length > 0 ? Math.max(...ports.value.map((p) => p.port)) + 1 : 80;
  ports.value.push({
    id: String(Date.now()),
    port: nextPort <= 65535 ? nextPort : 8080,
    scheme: 'http',
  });
};

const removePort = (idx: number) => {
  if (ports.value.length > 1) {
    ports.value.splice(idx, 1);
  }
};

// Upstream Management
const addUpstream = () => {
  upstreams.value.push({
    id: String(Date.now()),
    dial: 'http://127.0.0.1:8080',
    weight: 1,
  });
};

const removeUpstream = (idx: number) => {
  if (upstreams.value.length > 1) {
    upstreams.value.splice(idx, 1);
  }
};

// Form Submission
const handleSave = () => {
  addDomain();

  const cleanedHosts = domains.value.filter(Boolean);
  const finalHosts = cleanedHosts.length > 0 ? cleanedHosts : ['*'];

  const compiledUpstreams: Upstream[] = upstreams.value.map((u) => {
    let cleanDial = u.dial.trim();
    if (cleanDial.startsWith('http://')) {
      cleanDial = cleanDial.replace('http://', '');
    } else if (cleanDial.startsWith('https://')) {
      cleanDial = cleanDial.replace('https://', '');
    }
    const slashIdx = cleanDial.indexOf('/');
    if (slashIdx !== -1) {
      cleanDial = cleanDial.substring(0, slashIdx);
    }
    return {
      dial: cleanDial || '127.0.0.1:8080',
      weight: Number(u.weight) || 1,
    };
  });

  const finalName = appName.value.trim() || finalHosts[0] || 'Application';

  emit('save', {
    id: props.site?.id,
    name: finalName,
    hostnames: finalHosts,
    mode: formMode.value,
    upstreams: compiledUpstreams,
    block_status_code: formBlockCode.value,
    offline_status_code: formOfflineCode.value,
  });

  emit('close');
};

const handleOpenChange = (openState: boolean) => {
  if (!openState) {
    emit('close');
  }
};
</script>

<template>
  <Dialog :open="open" @update:open="handleOpenChange">
    <DialogContent class="max-w-xl max-h-[90vh] flex flex-col p-6 bg-card text-card-foreground font-sans rounded-xl border border-border shadow-none overflow-hidden">
      <!-- SafeLine Modal Header -->
      <div class="flex items-center justify-between pb-3 border-b border-border shrink-0">
        <h2 class="text-base font-semibold text-foreground">
          {{ site ? 'Edit Application' : 'Add Application' }}
        </h2>
        <button
          type="button"
          @click="$emit('close')"
          class="text-muted-foreground hover:text-foreground p-1 rounded-md transition-colors cursor-pointer"
          aria-label="Close"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- SafeLine Modal Form Body -->
      <div class="py-4 overflow-y-auto space-y-4 flex-1 pr-1">
        <!-- 1. Domain * with Tag Input -->
        <div class="space-y-1.5">
          <label class="text-xs font-semibold text-foreground flex items-center gap-1">
            <span>Domain</span>
            <span class="text-threat">*</span>
          </label>
          <div class="flex flex-wrap items-center gap-1.5 p-2 rounded-md border border-input bg-card min-h-[40px] focus-within:border-primary focus-within:ring-1 focus-within:ring-ring transition-colors">
            <span
              v-for="(domain, idx) in domains"
              :key="idx"
              class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-muted text-foreground text-xs font-mono font-medium border border-border"
            >
              <span>{{ domain }}</span>
              <button
                type="button"
                @click="removeDomain(idx)"
                class="text-muted-foreground hover:text-threat transition-colors cursor-pointer"
                title="Remove domain"
              >
                <X class="w-3 h-3" />
              </button>
            </span>
            <input
              v-model="domainInput"
              type="text"
              placeholder="www.example.com, support *"
              class="flex-1 bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none min-w-[180px]"
              @keydown.enter.prevent="addDomain"
              @keydown.comma.prevent="addDomain"
              @blur="addDomain"
            />
          </div>
        </div>

        <!-- 2. Listening Ports -->
        <div class="space-y-2">
          <label class="text-xs font-semibold text-foreground flex items-center gap-1">
            <span>Port</span>
            <span class="text-threat">*</span>
          </label>
          <div class="space-y-2">
            <div
              v-for="(p, idx) in ports"
              :key="p.id"
              class="flex items-center gap-2"
            >
              <div class="w-32">
                <NumberInput
                  v-model="p.port"
                  :min="1"
                  :max="65535"
                  placeholder="80"
                  class="h-9"
                />
              </div>

              <!-- HTTP / HTTPS Pill Toggle -->
              <div class="inline-flex rounded-md border border-input p-0.5 bg-muted/40 shrink-0">
                <button
                  type="button"
                  @click="p.scheme = 'http'"
                  :class="[
                    'px-3 py-1 text-xs rounded font-medium transition-colors cursor-pointer',
                    p.scheme === 'http'
                      ? 'bg-primary text-primary-foreground font-semibold shadow-none'
                      : 'text-muted-foreground hover:text-foreground'
                  ]"
                >
                  HTTP
                </button>
                <button
                  type="button"
                  @click="p.scheme = 'https'"
                  :class="[
                    'px-3 py-1 text-xs rounded font-medium transition-colors cursor-pointer',
                    p.scheme === 'https'
                      ? 'bg-primary text-primary-foreground font-semibold shadow-none'
                      : 'text-muted-foreground hover:text-foreground'
                  ]"
                >
                  HTTPS
                </button>
              </div>

              <!-- Delete Port Button -->
              <button
                type="button"
                :disabled="ports.length <= 1"
                @click="removePort(idx)"
                class="p-2 text-muted-foreground hover:text-threat disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer ml-auto"
                title="Remove port"
              >
                <Trash2 class="w-4 h-4" />
              </button>
            </div>
          </div>

          <!-- + ADD LISTENING PORT Button -->
          <Button
            type="button"
            variant="outline"
            class="w-full h-8 border-dashed border-primary/40 text-primary hover:bg-primary/5 text-xs font-semibold uppercase tracking-wider gap-1.5 shadow-none"
            @click="addPort"
          >
            <Plus class="w-3.5 h-3.5" />
            <span>ADD LISTENING PORT</span>
          </Button>
        </div>

        <!-- 3. SSL Cert Selector (when HTTPS port is active) -->
        <div v-if="hasHttpsPort" class="space-y-1.5">
          <label class="text-xs font-semibold text-foreground">SSL Cert</label>
          <Select v-model="sslCert">
            <SelectTrigger class="w-full h-9 text-xs">
              <SelectValue placeholder="Select certificate" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Auto ACME / Let's Encrypt (CertMagic)</SelectItem>
              <SelectItem value="default">Default Gateway Certificate</SelectItem>
              <SelectItem value="custom">Custom Uploaded Certificate</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <!-- 4. Routing Type Selector (Reverse Proxy / Static Files / Redirect) -->
        <div class="grid grid-cols-3 gap-2">
          <button
            type="button"
            @click="routingType = 'proxy'"
            :class="[
              'flex items-center justify-center gap-2 p-2.5 rounded-md border text-xs font-medium transition-colors cursor-pointer',
              routingType === 'proxy'
                ? 'border-primary text-primary bg-primary/5 font-semibold'
                : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/40'
            ]"
          >
            <span
              class="w-3.5 h-3.5 rounded-full border flex items-center justify-center"
              :class="routingType === 'proxy' ? 'border-primary' : 'border-muted-foreground/60'"
            >
              <span v-if="routingType === 'proxy'" class="w-1.5 h-1.5 rounded-full bg-primary" />
            </span>
            <span>Reverse Proxy</span>
          </button>

          <button
            type="button"
            @click="routingType = 'static'"
            :class="[
              'flex items-center justify-center gap-2 p-2.5 rounded-md border text-xs font-medium transition-colors cursor-pointer',
              routingType === 'static'
                ? 'border-primary text-primary bg-primary/5 font-semibold'
                : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/40'
            ]"
          >
            <span
              class="w-3.5 h-3.5 rounded-full border flex items-center justify-center"
              :class="routingType === 'static' ? 'border-primary' : 'border-muted-foreground/60'"
            >
              <span v-if="routingType === 'static'" class="w-1.5 h-1.5 rounded-full bg-primary" />
            </span>
            <span>Static Files</span>
          </button>

          <button
            type="button"
            @click="routingType = 'redirect'"
            :class="[
              'flex items-center justify-center gap-2 p-2.5 rounded-md border text-xs font-medium transition-colors cursor-pointer',
              routingType === 'redirect'
                ? 'border-primary text-primary bg-primary/5 font-semibold'
                : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/40'
            ]"
          >
            <span
              class="w-3.5 h-3.5 rounded-full border flex items-center justify-center"
              :class="routingType === 'redirect' ? 'border-primary' : 'border-muted-foreground/60'"
            >
              <span v-if="routingType === 'redirect'" class="w-1.5 h-1.5 rounded-full bg-primary" />
            </span>
            <span>Redirect</span>
          </button>
        </div>

        <!-- 5. Upstream Targets (Reverse Proxy Mode) -->
        <div v-if="routingType === 'proxy'" class="space-y-2">
          <label class="text-xs font-semibold text-foreground flex items-center gap-1">
            <span>Upstream</span>
            <span class="text-threat">*</span>
          </label>

          <div class="space-y-2">
            <div
              v-for="(u, idx) in upstreams"
              :key="u.id"
              class="flex items-center gap-2"
            >
              <div class="flex-1 min-w-0">
                <Input
                  v-model="u.dial"
                  placeholder="http://192.168.1.10:8080, not support path"
                  class="h-9 text-xs font-mono"
                />
              </div>

              <!-- Weight input when multiple upstreams exist -->
              <div v-if="upstreams.length > 1" class="w-24 shrink-0 flex items-center gap-1.5">
                <span class="text-xs text-muted-foreground">Weight</span>
                <NumberInput
                  v-model="u.weight"
                  :min="1"
                  :max="100"
                  class="h-9 w-14 text-xs font-mono"
                />
              </div>

              <!-- Delete Upstream Button -->
              <button
                type="button"
                :disabled="upstreams.length <= 1"
                @click="removeUpstream(idx)"
                class="p-2 text-muted-foreground hover:text-threat disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer shrink-0"
                title="Remove upstream"
              >
                <Trash2 class="w-4 h-4" />
              </button>
            </div>
          </div>

          <!-- + ADD UPSTREAM (i) Button -->
          <Button
            type="button"
            variant="outline"
            class="w-full h-8 border-dashed border-primary/40 text-primary hover:bg-primary/5 text-xs font-semibold uppercase tracking-wider gap-1.5 shadow-none"
            @click="addUpstream"
          >
            <Plus class="w-3.5 h-3.5" />
            <span>ADD UPSTREAM</span>
            <Info class="w-3.5 h-3.5 opacity-70 ml-0.5" />
          </Button>

          <!-- 6. Load Balancing Algorithm (when >= 2 upstreams) -->
          <div v-if="upstreams.length >= 2" class="space-y-1.5 pt-1">
            <label class="text-xs font-semibold text-foreground">Load Balancing Algorithm</label>
            <Select v-model="loadBalancing">
              <SelectTrigger class="w-full h-9 text-xs">
                <SelectValue placeholder="Select algorithm" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="round_robin">Round-robin</SelectItem>
                <SelectItem value="least_conn">Least Connections</SelectItem>
                <SelectItem value="ip_hash">IP Hash</SelectItem>
                <SelectItem value="primary_backup">Primary-Backup</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <!-- 7. Application Meta (Name & Description) -->
        <div class="space-y-3 pt-1 border-t border-border/60">
          <div class="space-y-1.5">
            <label class="text-xs font-semibold text-foreground">Application Name</label>
            <Input
              v-model="appName"
              placeholder="Application Name"
              class="h-9 text-xs"
            />
          </div>

          <div class="space-y-1.5">
            <label class="text-xs font-semibold text-foreground">Application Description</label>
            <Input
              v-model="appDescription"
              placeholder="Application Description"
              class="h-9 text-xs"
            />
          </div>
        </div>

        <!-- 8. Advanced Settings (Collapsible Accordion) -->
        <div class="border border-border/80 rounded-lg p-3 bg-muted/20 space-y-3">
          <button
            type="button"
            @click="advancedOpen = !advancedOpen"
            class="w-full flex items-center justify-between text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors cursor-pointer select-none"
          >
            <span>Advanced Protection Settings (Operational Mode & Status Codes)</span>
            <ChevronDown
              class="w-4 h-4 transition-transform duration-200"
              :class="{ 'rotate-180': advancedOpen }"
            />
          </button>

          <div v-if="advancedOpen" class="space-y-3 pt-2 border-t border-border/60">
            <div>
              <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                Operational Mode
              </label>
              <Select v-model="formMode">
                <SelectTrigger class="w-full h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="defense">Defense (Active Threat Blocking)</SelectItem>
                  <SelectItem value="audit">Audit (Log & Alert Only)</SelectItem>
                  <SelectItem value="offline">Offline (Maintenance 503)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                  Block HTTP Status
                </label>
                <NumberInput
                  v-model="formBlockCode"
                  :min="100"
                  :max="599"
                  placeholder="403"
                  class="h-8"
                />
              </div>

              <div>
                <label class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                  Offline HTTP Status
                </label>
                <NumberInput
                  v-model="formOfflineCode"
                  :min="100"
                  :max="599"
                  placeholder="503"
                  class="h-8"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- SafeLine Modal Footer -->
      <div class="flex items-center justify-end gap-3 pt-3 border-t border-border shrink-0">
        <Button
          type="button"
          variant="ghost"
          class="h-9 px-5 text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground"
          @click="$emit('close')"
        >
          CANCEL
        </Button>
        <Button
          type="button"
          class="h-9 px-6 text-xs font-semibold uppercase tracking-wider bg-primary text-primary-foreground hover:bg-primary/90 shadow-none"
          @click="handleSave"
        >
          SUBMIT
        </Button>
      </div>
    </DialogContent>
  </Dialog>
</template>
