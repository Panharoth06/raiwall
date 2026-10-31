<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import {
  detectionApi,
  type RulePackValidation,
} from '@/api/detection';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import RulePackFileDropzone from '@/components/detection/RulePackFileDropzone.vue';
import {
  AlertTriangle,
  CheckCircle2,
  FileCode2,
  Loader2,
  Package,
  Plus,
  ShieldCheck,
  Sparkles,
  Upload,
} from 'lucide-vue-next';

const props = defineProps<{
  open: boolean;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'saved', count: number): void;
}>();

type PackType = 'native' | 'modsec' | 'crs';
type Relation = 'additive' | 'replace';

const packName = ref('');
const packVersion = ref('1.0.0');
const packType = ref<PackType>('native');
const relation = ref<Relation>('additive');
const rulesJson = ref('');
const directives = ref('');
const files = ref<Record<string, string>>({});
const validation = ref<RulePackValidation | null>(null);
const validating = ref(false);
const installing = ref(false);
const error = ref('');
const successMsg = ref('');

const sampleRules = `[
  {
    "id": "CUSTOM-CVE-2024-0001",
    "name": "Custom Critical Zero-Day Exploit Patch",
    "category": "rce",
    "methods": ["POST", "GET"],
    "prefix": "/api/v1/auth",
    "matches": [
      { "field": "body", "token": "eval(base64_decode" }
    ]
  }
]`;

const sampleDirectives = `SecRule REQUEST_URI "@contains /evil" \\
  "id:10001,phase:1,deny,status:403,msg:'Custom request block'"
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)scanner" \\
  "id:10002,phase:1,pass,log,setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},msg:'Scanner user agent'"`;

const parsedRules = computed(() => {
  const raw = rulesJson.value.trim();
  if (!raw) return [] as unknown[];
  try {
    const value = JSON.parse(raw);
    return Array.isArray(value) ? value : (null as unknown[] | null);
  } catch {
    return null as unknown[] | null;
  }
});

const fileCount = computed(() => Object.keys(files.value).length);

const canSubmit = computed(() => {
  if (!packName.value.trim()) return false;
  if (packType.value === 'native') {
    return parsedRules.value !== null && parsedRules.value.length > 0;
  }
  return directives.value.trim().length > 0 || fileCount.value > 0;
});

const resetFeedback = () => {
  validation.value = null;
  error.value = '';
  successMsg.value = '';
};

watch(packType, () => {
  resetFeedback();
  if (packType.value !== 'crs') relation.value = 'additive';
});

const setType = (type: PackType) => {
  packType.value = type;
};

const loadTemplate = () => {
  resetFeedback();
  if (packType.value === 'native') {
    packName.value = packName.value || 'Security Team Native Patch Pack';
    rulesJson.value = sampleRules;
  } else {
    packName.value = packName.value || 'Security Team ModSecurity Pack';
    directives.value = sampleDirectives;
  }
};

const clearFiles = () => {
  files.value = {};
  resetFeedback();
};

const buildPayload = () => {
  if (packType.value === 'native') {
    return {
      name: packName.value.trim(),
      version: packVersion.value.trim() || '1.0.0',
      type: 'native',
      relation: 'additive',
      rules: parsedRules.value ?? [],
    };
  }
  return {
    name: packName.value.trim(),
    version: packVersion.value.trim() || '1.0.0',
    type: packType.value,
    relation: packType.value === 'crs' ? relation.value : 'additive',
    directives: directives.value,
    files: files.value,
  };
};

const validatePack = async () => {
  resetFeedback();
  if (!canSubmit.value) {
    error.value = packType.value === 'native'
      ? 'Provide a pack name and a valid JSON rule array.'
      : 'Provide a pack name and directive text or at least one .conf file.';
    return;
  }
  validating.value = true;
  try {
    validation.value = await detectionApi.validatePack(buildPayload());
    if (!validation.value.valid) {
      error.value = validation.value.errors?.join(' · ') || 'Pack validation failed.';
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Validation failed';
  } finally {
    validating.value = false;
  }
};

const install = async () => {
  if (!canSubmit.value) return;
  resetFeedback();
  installing.value = true;
  try {
    if (!validation.value?.valid) {
      validation.value = await detectionApi.validatePack(buildPayload());
      if (!validation.value.valid) {
        error.value = validation.value.errors?.join(' · ') || 'Pack validation failed.';
        return;
      }
    }
    const result = await detectionApi.createPack(buildPayload());
    successMsg.value = `${result.pack.name} v${result.pack.version} installed with ${result.pack.rules_count} rule(s).`;
    emit('saved', result.pack.rules_count);
    emit('close');
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Install failed';
  } finally {
    installing.value = false;
  }
};
</script>

<template>
  <Dialog :open="open" @update:open="(value) => !value && emit('close')">
    <DialogContent class="max-w-2xl max-h-[90vh] overflow-y-auto font-sans p-6" data-testid="rule-pack-import-dialog">
      <!-- Modal Header -->
      <DialogHeader class="pb-3 border-b border-border">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20 shrink-0">
              <Upload class="w-5 h-5" />
            </div>
            <div>
              <DialogTitle class="text-base font-semibold text-foreground flex items-center gap-2">
                <span>Install Rule Pack</span>
              </DialogTitle>
              <DialogDescription class="text-xs text-muted-foreground mt-0.5">
                Validate and compile signature packs before promoting to the active data plane snapshot.
              </DialogDescription>
            </div>
          </div>
          <Badge variant="outline" class="font-mono text-xs uppercase text-muted-foreground shrink-0 hidden sm:inline-flex">
            Native · ModSec
          </Badge>
        </div>
      </DialogHeader>

      <div class="space-y-4 py-3 text-xs">
        <!-- Pack Metadata Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <div class="sm:col-span-2 space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Pack Name</label>
            <Input
              v-model="packName"
              placeholder="e.g. Corporate Security Baseline"
              class="text-xs font-sans h-8"
              data-testid="rule-pack-name-input"
            />
          </div>
          <div class="space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Version</label>
            <Input
              v-model="packVersion"
              placeholder="1.0.0"
              class="text-xs font-mono h-8"
              data-testid="rule-pack-version-input"
            />
          </div>
          <div class="space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Relation</label>
            <Select
              v-if="packType === 'crs'"
              :model-value="relation"
              @update:model-value="(value) => (relation = value as Relation)"
            >
              <SelectTrigger class="h-8 text-xs bg-card border-border text-foreground" data-testid="rule-pack-relation">
                <SelectValue />
              </SelectTrigger>
              <SelectContent class="border-border bg-popover text-popover-foreground">
                <SelectItem value="additive" class="text-xs">Additive</SelectItem>
                <SelectItem value="replace" class="text-xs">Replace embedded CRS</SelectItem>
              </SelectContent>
            </Select>
            <div
              v-else
              class="flex h-8 items-center rounded-md border border-border bg-muted/40 px-3 font-mono text-xs text-muted-foreground"
            >
              additive
            </div>
          </div>
        </div>

        <!-- Rule Format Segmented Control -->
        <div class="space-y-1.5">
          <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Rule Format</label>
          <div class="grid grid-cols-3 gap-1 p-1 bg-muted/40 border border-border rounded-lg">
            <button
              type="button"
              class="flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-medium transition-all cursor-pointer"
              :class="packType === 'native' ? 'bg-card text-foreground shadow-sm border border-border font-semibold' : 'text-muted-foreground hover:text-foreground'"
              data-testid="rule-pack-type-native"
              @click="setType('native')"
            >
              <FileCode2 class="w-3.5 h-3.5" :class="packType === 'native' ? 'text-primary' : 'text-muted-foreground'" />
              <span>Native JSON</span>
            </button>
            <button
              type="button"
              class="flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-medium transition-all cursor-pointer"
              :class="packType === 'modsec' ? 'bg-card text-foreground shadow-sm border border-border font-semibold' : 'text-muted-foreground hover:text-foreground'"
              data-testid="rule-pack-type-modsec"
              @click="setType('modsec')"
            >
              <ShieldCheck class="w-3.5 h-3.5" :class="packType === 'modsec' ? 'text-primary' : 'text-muted-foreground'" />
              <span>ModSecurity</span>
            </button>
            <button
              type="button"
              class="flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-medium transition-all cursor-pointer"
              :class="packType === 'crs' ? 'bg-card text-foreground shadow-sm border border-border font-semibold' : 'text-muted-foreground hover:text-foreground'"
              data-testid="rule-pack-type-crs"
              @click="setType('crs')"
            >
              <Package class="w-3.5 h-3.5" :class="packType === 'crs' ? 'text-primary' : 'text-muted-foreground'" />
              <span>CRS Bundle</span>
            </button>
          </div>
        </div>

        <!-- Native JSON Format Area -->
        <div v-if="packType === 'native'" class="space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Signature Definitions (JSON Array)
            </span>
            <Button
              variant="ghost"
              size="sm"
              class="h-6 px-2 text-xs text-primary gap-1"
              @click="loadTemplate"
            >
              <Sparkles class="w-3 h-3" />
              <span>Load Template</span>
            </Button>
          </div>
          <div class="rounded-lg border border-border bg-card overflow-hidden focus-within:border-primary focus-within:ring-1 focus-within:ring-primary transition-all">
            <textarea
              v-model="rulesJson"
              rows="7"
              placeholder="[{ &quot;id&quot;: &quot;CVE-2024-XXXX&quot;, &quot;name&quot;: &quot;...&quot;, &quot;matches&quot;: [...] }]"
              class="w-full bg-transparent p-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none resize-y"
              data-testid="rule-pack-json-input"
            />
            <div class="flex items-center justify-between px-3 py-1.5 bg-muted/40 border-t border-border text-xs text-muted-foreground">
              <span v-if="parsedRules === null" class="text-threat font-medium">Invalid JSON syntax</span>
              <span v-else-if="parsedRules.length > 0" class="text-success font-medium">
                ✓ {{ parsedRules.length }} signature rule(s) parsed
              </span>
              <span v-else>Paste JSON array of CVE virtual patch signatures</span>
              <span class="font-mono">Fast token indexing</span>
            </div>
          </div>
        </div>

        <!-- ModSecurity / CRS Directives & Dropzone -->
        <div v-else class="space-y-3">
          <div class="space-y-1.5">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Directive Text
              </span>
              <Button
                variant="ghost"
                size="sm"
                class="h-6 px-2 text-xs text-primary gap-1"
                @click="loadTemplate"
              >
                <Sparkles class="w-3 h-3" />
                <span>Load Template</span>
              </Button>
            </div>
            <div class="rounded-lg border border-border bg-card overflow-hidden focus-within:border-primary focus-within:ring-1 focus-within:ring-primary transition-all">
              <textarea
                v-model="directives"
                rows="7"
                placeholder="SecRule REQUEST_URI &quot;@contains /evil&quot; &quot;id:10001,phase:1,deny,status:403,msg:'Custom block'&quot;"
                class="w-full bg-transparent p-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none resize-y"
                data-testid="rule-pack-directives-input"
              />
              <div class="flex items-center justify-between px-3 py-1.5 bg-muted/40 border-t border-border text-xs text-muted-foreground">
                <span>ModSecurity 2.x directive grammar</span>
                <span class="font-mono">Compiled by Coraza</span>
              </div>
            </div>
          </div>

          <!-- Professional Drag & Drop File Zone (Bans Native Browser Choose Files button) -->
          <div class="space-y-1.5">
            <span class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Include Files (.conf / .data)
            </span>
            <RulePackFileDropzone
              :files="files"
              @update:files="(next) => { files = next; resetFeedback(); }"
              @clear="clearFiles"
            />
          </div>
        </div>

        <!-- Validation Result Feedback Banner -->
        <div
          v-if="validation"
          class="rounded-lg border p-3 space-y-1.5"
          :class="validation.valid ? 'border-success/30 bg-success/10 text-success' : 'border-threat/30 bg-threat/10 text-threat'"
          data-testid="rule-pack-validation-result"
        >
          <div class="flex items-center gap-2 font-medium text-xs">
            <CheckCircle2 v-if="validation.valid" class="w-4 h-4 shrink-0" />
            <AlertTriangle v-else class="w-4 h-4 shrink-0" />
            <span>
              {{ validation.valid ? 'Pack compiled and verified successfully' : 'Pack compilation rejected' }}
              · {{ validation.rules_parsed }} rule(s) parsed
            </span>
          </div>
          <ul v-if="validation.errors?.length" class="space-y-1 font-mono text-xs pl-6 list-disc">
            <li v-for="(message, index) in validation.errors" :key="index">{{ message }}</li>
          </ul>
        </div>

        <div v-if="error" class="p-3 bg-threat/10 border border-threat/30 rounded-lg flex items-center gap-2 text-threat">
          <AlertTriangle class="w-4 h-4 shrink-0" />
          <span class="break-all text-xs">{{ error }}</span>
        </div>
        <div v-if="successMsg" class="p-3 bg-success/10 border border-success/30 rounded-lg flex items-center gap-2 text-success">
          <CheckCircle2 class="w-4 h-4 shrink-0" />
          <span class="text-xs">{{ successMsg }}</span>
        </div>
      </div>

      <!-- Modal Footer -->
      <DialogFooter class="pt-3 border-t border-border gap-2 sm:justify-between flex-wrap">
        <Button variant="outline" size="sm" class="h-8 text-xs" :disabled="installing" @click="emit('close')">
          Cancel
        </Button>
        <div class="flex items-center gap-2 ml-auto">
          <Button
            variant="outline"
            size="sm"
            class="gap-1.5 h-8 text-xs"
            :disabled="!canSubmit || validating || installing"
            data-testid="rule-pack-validate-btn"
            @click="validatePack"
          >
            <Loader2 v-if="validating" class="w-3.5 h-3.5 animate-spin" />
            <ShieldCheck v-else class="w-3.5 h-3.5 text-primary" />
            <span>Validate</span>
          </Button>
          <Button
            size="sm"
            class="gap-1.5 h-8 text-xs font-semibold"
            :disabled="!canSubmit || installing || validating"
            data-testid="rule-pack-submit-btn"
            @click="install"
          >
            <Loader2 v-if="installing" class="w-3.5 h-3.5 animate-spin" />
            <Plus v-else class="w-3.5 h-3.5" />
            <span>{{ installing ? 'Installing…' : 'Install Pack' }}</span>
          </Button>
        </div>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
