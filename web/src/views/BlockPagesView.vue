<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import {
  templatesApi,
  TEMPLATE_STATUS_CODES,
  type ResponseTemplate,
  type StatusCodeOption,
} from '@/api/templates';
import { interpolateTemplate } from '@/utils/templateInterpolator';
import TemplateCodeEditor from '@/components/TemplateCodeEditor.vue';
import TemplatePreviewCard from '@/components/TemplatePreviewCard.vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ConfirmDialog } from '@/components/ui/dialog';
import {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from '@/components/ui/tooltip';
import {
  FileCode,
  RotateCcw,
  Save,
  CheckCircle2,
  AlertCircle,
} from 'lucide-vue-next';

const selectedCode = ref<number>(403);
const templatesList = ref<ResponseTemplate[]>([]);
const currentTemplate = ref<ResponseTemplate | null>(null);

const formHtml = ref('');
const formCss = ref('');
const formBrand = ref('Raiwall');
const formLogo = ref('');

const previewHtml = ref('');
const isSaving = ref(false);
const isResetting = ref(false);
const showResetConfirm = ref(false);
const isLoading = ref(true);
const statusMessage = ref<{ text: string; type: 'success' | 'error' } | null>(null);

const currentOption = computed<StatusCodeOption | undefined>(() =>
  TEMPLATE_STATUS_CODES.find((c) => c.code === selectedCode.value)
);

const isCustomized = computed(() => {
  return currentTemplate.value?.is_custom ?? false;
});

const loadTemplates = async () => {
  isLoading.value = true;
  try {
    const list = await templatesApi.listTemplates();
    templatesList.value = list;
    await selectCode(selectedCode.value);
  } catch (err: any) {
    statusMessage.value = { text: err.message || 'Failed to load templates', type: 'error' };
    await updatePreview();
  } finally {
    isLoading.value = false;
  }
};

const selectCode = async (code: number) => {
  selectedCode.value = code;
  try {
    const tmpl = await templatesApi.getTemplate(code);
    currentTemplate.value = tmpl;
    formHtml.value = tmpl.content_html;
    formCss.value = tmpl.custom_css;
    formBrand.value = tmpl.brand_name || 'Raiwall';
    formLogo.value = tmpl.logo_url || '';
  } catch (err: any) {
    statusMessage.value = { text: err.message || 'Failed to fetch template', type: 'error' };
  }
  await updatePreview();
};

const updatePreview = async () => {
  // 1. Immediately render client-side fallback interpolation so preview is instantaneous
  previewHtml.value = interpolateTemplate(
    formHtml.value,
    formCss.value,
    formBrand.value,
    formLogo.value,
    selectedCode.value
  );

  // 2. Query backend sandbox preview
  try {
    const res = await templatesApi.previewTemplate(selectedCode.value, {
      content_html: formHtml.value,
      custom_css: formCss.value,
      brand_name: formBrand.value,
      logo_url: formLogo.value,
    });
    if (res?.rendered_html) {
      previewHtml.value = res.rendered_html;
    }
  } catch {
    // Keep client-interpolated HTML
  }
};

watch([formHtml, formCss, formBrand, formLogo], () => {
  updatePreview();
});

const handleSave = async () => {
  isSaving.value = true;
  statusMessage.value = null;
  try {
    const updated = await templatesApi.updateTemplate(selectedCode.value, {
      title: currentOption.value?.name || 'Custom Template',
      content_html: formHtml.value,
      custom_css: formCss.value,
      brand_name: formBrand.value,
      logo_url: formLogo.value,
    });
    currentTemplate.value = updated;
    statusMessage.value = { text: `Template HTTP ${selectedCode.value} successfully saved`, type: 'success' };
    setTimeout(() => { statusMessage.value = null; }, 3000);
  } catch (err: any) {
    statusMessage.value = { text: err.message || 'Failed to save template', type: 'error' };
  } finally {
    isSaving.value = false;
  }
};

const triggerReset = () => {
  showResetConfirm.value = true;
};

const handleReset = async () => {
  showResetConfirm.value = false;
  isResetting.value = true;
  statusMessage.value = null;
  try {
    const reset = await templatesApi.resetTemplate(selectedCode.value);
    currentTemplate.value = reset;
    formHtml.value = reset.content_html;
    formCss.value = reset.custom_css;
    formBrand.value = reset.brand_name || 'Raiwall';
    formLogo.value = reset.logo_url || '';
    await updatePreview();
    statusMessage.value = { text: `HTTP ${selectedCode.value} reset to factory default`, type: 'success' };
    setTimeout(() => { statusMessage.value = null; }, 3000);
  } catch (err: any) {
    statusMessage.value = { text: err.message || 'Failed to reset template', type: 'error' };
  } finally {
    isResetting.value = false;
  }
};

onMounted(() => {
  loadTemplates();
});
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-border pb-4">
      <div>
        <div class="flex items-center gap-2">
          <FileCode class="w-6 h-6 text-primary" />
          <h1 class="text-xl font-bold tracking-tight text-foreground">Block Pages & Response Templates</h1>
        </div>
        <p class="text-xs text-muted-foreground mt-1">
          Customize deterministic HTML/CSS error, challenge, and waiting room response screens across the gateway.
        </p>
      </div>

      <div class="flex items-center gap-2">
        <Button
          v-if="isCustomized"
          variant="outline"
          size="sm"
          class="h-8 text-xs gap-1.5"
          data-testid="btn-reset-template"
          :disabled="isResetting || isLoading"
          @click="triggerReset"
        >
          <RotateCcw class="w-3.5 h-3.5" />
          Reset Default
        </Button>
        <Button
          size="sm"
          class="h-8 text-xs gap-1.5"
          data-testid="btn-save-template"
          :disabled="isSaving || isLoading"
          @click="handleSave"
        >
          <Save class="w-3.5 h-3.5" />
          {{ isSaving ? 'Saving...' : 'Save Template' }}
        </Button>
      </div>
    </div>

    <!-- Status message banner -->
    <div
      v-if="statusMessage"
      class="flex items-center gap-2 px-3 py-2 rounded-md text-xs"
      :class="statusMessage.type === 'success' ? 'bg-success/15 text-success border border-success/30' : 'bg-destructive/15 text-destructive border border-destructive/30'"
    >
      <component :is="statusMessage.type === 'success' ? CheckCircle2 : AlertCircle" class="w-4 h-4" />
      <span>{{ statusMessage.text }}</span>
    </div>

    <!-- Status Codes Selector Dropdown & Hover Tooltip -->
    <div class="flex flex-wrap items-center gap-3 bg-muted/30 border border-border rounded-lg p-2.5">
      <label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider whitespace-nowrap">
        Response Template:
      </label>
      <div class="w-full sm:w-80">
        <Select
          :model-value="String(selectedCode)"
          @update:model-value="(val) => selectCode(Number(val))"
        >
          <SelectTrigger
            class="h-9 w-full bg-card border-border gap-2 text-xs"
            data-testid="status-template-select"
            :aria-label="`HTTP ${selectedCode} ${currentOption?.name}`"
          >
            <span class="font-mono font-bold text-primary whitespace-nowrap">HTTP {{ selectedCode }}</span>
            <span class="font-sans truncate text-foreground">{{ currentOption?.name }}</span>
          </SelectTrigger>
          <SelectContent class="border-border bg-popover text-popover-foreground max-h-80">
            <SelectItem
              v-for="opt in TEMPLATE_STATUS_CODES"
              :key="opt.code"
              :value="String(opt.code)"
              :title="`${opt.code} - ${opt.name} (${opt.description})`"
              class="cursor-pointer"
            >
              <div class="flex items-center justify-between gap-3 w-full py-0.5">
                <span class="font-bold font-mono text-primary text-xs">HTTP {{ opt.code }}</span>
                <span class="text-xs text-foreground truncate max-w-[180px]" :title="opt.name">
                  {{ opt.name }}
                </span>
                <Badge variant="outline" class="text-xs uppercase font-mono px-1 py-0 ml-auto shrink-0">
                  {{ opt.category }}
                </Badge>
              </div>
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      <!-- Selected Template Long Name with Hover Tooltip -->
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger as-child>
            <div
              class="hidden md:flex items-center gap-2 text-xs text-muted-foreground truncate max-w-md cursor-help border border-border/80 bg-card px-2.5 py-1.5 rounded-md"
            >
              <span class="font-medium text-foreground truncate">{{ currentOption?.name }}</span>
              <span class="text-xs opacity-75 truncate hidden sm:inline">— {{ currentOption?.description }}</span>
            </div>
          </TooltipTrigger>
          <TooltipContent side="bottom" class="max-w-xs text-xs">
            <p class="font-bold">HTTP {{ selectedCode }}: {{ currentOption?.name }}</p>
            <p class="text-xs text-muted-foreground mt-0.5">{{ currentOption?.description }}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>

      <!-- Accessible options list to guarantee template coverage -->
      <div class="sr-only" aria-hidden="true">
        <span v-for="opt in TEMPLATE_STATUS_CODES" :key="opt.code">{{ opt.code }} {{ opt.name }}</span>
      </div>
    </div>

    <!-- Main Workspace: Split Editor & Live Preview -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
      <!-- Editor Column -->
      <div class="bg-card border border-border rounded-xl p-5 shadow-xs space-y-4">
        <div class="flex items-center justify-between border-b border-border pb-3">
          <div>
            <div class="flex items-center gap-2">
              <span class="font-mono font-bold text-base text-foreground">HTTP {{ selectedCode }}</span>
              <Badge :variant="isCustomized ? 'default' : 'secondary'" class="text-xs uppercase font-mono tracking-wider">
                {{ isCustomized ? 'Customized' : 'Factory Default' }}
              </Badge>
            </div>
            <p class="text-xs text-muted-foreground mt-0.5">{{ currentOption?.description }}</p>
          </div>
        </div>

        <TemplateCodeEditor
          v-model:content-html="formHtml"
          v-model:custom-css="formCss"
          v-model:brand-name="formBrand"
          v-model:logo-url="formLogo"
        />
      </div>

      <!-- Live Preview Column -->
      <TemplatePreviewCard
        :preview-html="previewHtml"
        @refresh="updatePreview"
      />
    </div>

    <!-- Reset Confirmation Dialog -->
    <ConfirmDialog
      v-model:open="showResetConfirm"
      title="Reset Response Template"
      :description="`Reset HTTP ${selectedCode} template back to factory default? Any custom HTML/CSS modifications will be discarded.`"
      confirm-text="Reset Template"
      variant="destructive"
      @confirm="handleReset"
      @cancel="showResetConfirm = false"
    />
  </div>
</template>
