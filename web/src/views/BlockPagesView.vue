<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import {
  templatesApi,
  TEMPLATE_STATUS_CODES,
  type ResponseTemplate,
  type StatusCodeOption,
} from '@/api/templates';
import TemplateCodeEditor from '@/components/TemplateCodeEditor.vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  FileCode,
  RotateCcw,
  Save,
  Monitor,
  Tablet,
  Smartphone,
  Eye,
  RefreshCw,
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
const previewViewport = ref<'desktop' | 'tablet' | 'mobile'>('desktop');
const isSaving = ref(false);
const isResetting = ref(false);
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
    await updatePreview();
  } catch (err: any) {
    statusMessage.value = { text: err.message || 'Failed to fetch template', type: 'error' };
  }
};

const updatePreview = async () => {
  try {
    const res = await templatesApi.previewTemplate(selectedCode.value, {
      content_html: formHtml.value,
      custom_css: formCss.value,
      brand_name: formBrand.value,
      logo_url: formLogo.value,
    });
    previewHtml.value = res.html;
  } catch {
    previewHtml.value = formHtml.value;
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

const handleReset = async () => {
  if (!confirm(`Reset HTTP ${selectedCode.value} template back to factory default?`)) return;
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
          @click="handleReset"
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

    <!-- Status Codes Selector Bar -->
    <div class="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
      <button
        v-for="opt in TEMPLATE_STATUS_CODES"
        :key="opt.code"
        type="button"
        class="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors whitespace-nowrap cursor-pointer"
        :class="selectedCode === opt.code
          ? 'bg-primary text-primary-foreground border-primary shadow-xs'
          : 'bg-card text-muted-foreground border-border hover:bg-accent hover:text-foreground'"
        @click="selectCode(opt.code)"
      >
        <span class="font-bold">{{ opt.code }}</span>
        <span class="text-[11px] font-sans opacity-90">{{ opt.name.split(' ')[0] }}</span>
      </button>
    </div>

    <!-- Main Workspace: Split Editor & Live Preview -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
      <!-- Editor Column -->
      <div class="bg-card border border-border rounded-xl p-4 shadow-xs space-y-4">
        <div class="flex items-center justify-between border-b border-border pb-3">
          <div>
            <div class="flex items-center gap-2">
              <span class="font-mono font-bold text-sm text-foreground">HTTP {{ selectedCode }}</span>
              <Badge :variant="isCustomized ? 'default' : 'secondary'" class="text-[10px] uppercase font-mono tracking-wider">
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
      <div class="bg-card border border-border rounded-xl p-4 shadow-xs flex flex-col space-y-3">
        <div class="flex items-center justify-between border-b border-border pb-3">
          <div class="flex items-center gap-2">
            <Eye class="w-4 h-4 text-primary" />
            <span class="text-xs font-semibold text-foreground">Live Sandboxed Preview</span>
          </div>

          <!-- Viewport Toggle Buttons -->
          <div class="flex items-center gap-1 bg-muted p-0.5 rounded-md border border-border">
            <button
              type="button"
              class="p-1 rounded text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
              :class="{ 'bg-background text-foreground shadow-xs': previewViewport === 'desktop' }"
              title="Desktop (100%)"
              @click="previewViewport = 'desktop'"
            >
              <Monitor class="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              class="p-1 rounded text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
              :class="{ 'bg-background text-foreground shadow-xs': previewViewport === 'tablet' }"
              title="Tablet (768px)"
              @click="previewViewport = 'tablet'"
            >
              <Tablet class="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              class="p-1 rounded text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
              :class="{ 'bg-background text-foreground shadow-xs': previewViewport === 'mobile' }"
              title="Mobile (375px)"
              @click="previewViewport = 'mobile'"
            >
              <Smartphone class="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              class="p-1 rounded text-muted-foreground hover:text-foreground transition-colors cursor-pointer ml-1"
              title="Force Refresh"
              @click="updatePreview"
            >
              <RefreshCw class="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <!-- Sandboxed iframe container -->
        <div class="w-full flex justify-center bg-muted/40 border border-border rounded-lg overflow-hidden min-h-[500px] p-2">
          <div
            class="transition-all duration-200 shadow-sm bg-background border border-border rounded overflow-hidden"
            :style="{
              width: previewViewport === 'mobile' ? '375px' : previewViewport === 'tablet' ? '768px' : '100%',
              height: '520px',
            }"
          >
            <iframe
              :srcdoc="previewHtml"
              sandbox="allow-same-origin"
              class="w-full h-full border-none"
              title="Response Template Preview"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
