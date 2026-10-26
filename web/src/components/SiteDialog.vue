<script setup lang="ts">
import { computed } from 'vue';
import type { ManagedCertificate, Site } from '@/api/client';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { NumberInput } from '@/components/ui/number-input';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { X, ChevronDown } from 'lucide-vue-next';
import SiteTlsFields from './site-dialog/SiteTlsFields.vue';
import SiteRoutingFields from './site-dialog/SiteRoutingFields.vue';
import { useSiteForm } from './site-dialog/useSiteForm';

const props = withDefaults(
  defineProps<{
    open: boolean;
    site?: Site | null;
    certificates?: ManagedCertificate[];
    submitting?: boolean;
    error?: string | null;
  }>(),
  {
    site: null,
    certificates: () => [],
    submitting: false,
    error: null,
  }
);

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', site: Partial<Site>): void;
}>();

const form = useSiteForm(() => props.site);

const {
  appName,
  appDescription,
  domains,
  domainInput,
  ports,
  sslMode,
  certificateId,
  routingType,
  upstreams,
  loadBalancing,
  documentRoot,
  redirectUrl,
  redirectStatus,
  formMode,
  formBlockCode,
  formOfflineCode,
  advancedOpen,
  hasHttpsPort,
  validationError,
  addDomain,
  removeDomain,
  addPort,
  removePort,
  addUpstream,
  removeUpstream,
  certificateGroups,
  buildPayload,
} = form;

const groups = computed(() => certificateGroups(props.certificates));

const submit = () => {
  const result = buildPayload();
  if (!result.payload) {
    validationError.value = result.error || 'Check the form for invalid values.';
    return;
  }
  emit('save', result.payload);
};

const handleOpenChange = (openState: boolean) => {
  if (!openState) emit('close');
};
</script>

<template>
  <Dialog :open="open" @update:open="handleOpenChange">
    <DialogContent
      class="max-w-xl max-h-[90vh] flex flex-col p-6 bg-card text-card-foreground font-sans rounded-xl border border-border shadow-none overflow-hidden"
    >
      <div class="flex items-center justify-between pb-3 border-b border-border shrink-0">
        <div>
          <DialogTitle class="text-base font-semibold text-foreground">
            {{ site ? 'Edit Application' : 'Add Application' }}
          </DialogTitle>
          <DialogDescription class="text-xs text-muted-foreground mt-0.5">
            Changes stay in the draft until you apply them.
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
          <label class="text-xs font-semibold text-foreground flex items-center gap-1">
            <span>Domain</span>
            <span class="text-threat">*</span>
          </label>
          <div
            class="flex flex-wrap items-center gap-1.5 p-2 rounded-md border border-input bg-card min-h-[40px] focus-within:border-primary focus-within:ring-1 focus-within:ring-ring transition-colors"
          >
            <span
              v-for="(domain, idx) in domains"
              :key="domain"
              class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-muted text-foreground text-xs font-mono font-medium border border-border"
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
              placeholder="www.example.com, support *"
              class="flex-1 bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none min-w-[180px]"
              @keydown.enter.prevent="addDomain"
              @keydown.comma.prevent="addDomain"
              @blur="addDomain"
            />
          </div>
          <p class="text-xs text-muted-foreground">
            Wildcards like <span class="font-mono">*.example.com</span> are supported. Use
            <span class="font-mono">*</span> to match any host.
          </p>
        </div>

        <SiteTlsFields
          v-model:ports="ports"
          v-model:ssl-mode="sslMode"
          v-model:certificate-id="certificateId"
          :certificates="certificates"
          :usable-certificates="groups.usable"
          :unusable-certificates="groups.unusable"
          :has-https-port="hasHttpsPort"
          @add-port="addPort"
          @remove-port="removePort"
        />

        <SiteRoutingFields
          v-model:routing-type="routingType"
          v-model:upstreams="upstreams"
          v-model:load-balancing="loadBalancing"
          v-model:document-root="documentRoot"
          v-model:redirect-url="redirectUrl"
          v-model:redirect-status="redirectStatus"
          @add-upstream="addUpstream"
          @remove-upstream="removeUpstream"
        />

        <div class="space-y-3 pt-1 border-t border-border/60">
          <div class="space-y-1.5">
            <label class="text-xs font-semibold text-foreground">Application Name</label>
            <Input v-model="appName" placeholder="Application Name" class="h-9 text-xs" />
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

        <div class="border border-border/80 rounded-lg p-3 bg-muted/20 space-y-3">
          <button
            type="button"
            class="w-full flex items-center justify-between text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors cursor-pointer select-none"
            @click="advancedOpen = !advancedOpen"
          >
            <span>Advanced Protection Settings (Operational Mode &amp; Status Codes)</span>
            <ChevronDown
              class="w-4 h-4 transition-transform duration-150"
              :class="{ 'rotate-180': advancedOpen }"
            />
          </button>

          <div v-if="advancedOpen" class="space-y-3 pt-2 border-t border-border/60">
            <div>
              <label
                class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1"
              >
                Operational Mode
              </label>
              <Select v-model="formMode">
                <SelectTrigger class="w-full h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="defense">Defense (Active Threat Blocking)</SelectItem>
                  <SelectItem value="audit">Audit (Log &amp; Alert Only)</SelectItem>
                  <SelectItem value="offline">Offline (Maintenance 503)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label
                  class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1"
                >
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
                <label
                  class="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1"
                >
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

        <p
          v-if="validationError || error"
          class="text-xs text-threat border border-threat/30 bg-threat/5 rounded-md px-3 py-2"
          role="alert"
        >
          {{ validationError || error }}
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
          class="h-9 px-6 text-xs font-semibold uppercase tracking-wider bg-primary text-primary-foreground hover:bg-primary/90 shadow-none"
          :disabled="submitting"
          @click="submit"
        >
          {{ submitting ? 'SAVING…' : 'SUBMIT' }}
        </Button>
      </div>
    </DialogContent>
  </Dialog>
</template>
