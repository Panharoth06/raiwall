<script setup lang="ts">
import { ref, computed } from 'vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { UploadCloud, FileText, Trash2, X, Plus } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    files: Record<string, string>;
    disabled?: boolean;
  }>(),
  {
    disabled: false,
  }
);

const emit = defineEmits<{
  (e: 'update:files', files: Record<string, string>): void;
  (e: 'clear'): void;
}>();

const fileInputRef = ref<HTMLInputElement | null>(null);
const isDragging = ref(false);

const filesList = computed(() => {
  return Object.entries(props.files).map(([name, content]) => ({
    name,
    lines: content ? content.split('\n').length : 0,
    sizeBytes: new Blob([content]).size,
  }));
});

const triggerBrowse = () => {
  if (props.disabled) return;
  fileInputRef.value?.click();
};

const processFiles = async (fileList: FileList | null) => {
  if (!fileList || fileList.length === 0) return;
  const next: Record<string, string> = { ...props.files };
  for (const file of Array.from(fileList)) {
    const relative = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
    next[relative] = await file.text();
  }
  emit('update:files', next);
  if (fileInputRef.value) fileInputRef.value.value = '';
};

const onFileInputChange = (event: Event) => {
  const input = event.target as HTMLInputElement;
  void processFiles(input.files);
};

const onDragOver = (e: DragEvent) => {
  e.preventDefault();
  if (props.disabled) return;
  isDragging.value = true;
};

const onDragLeave = () => {
  isDragging.value = false;
};

const onDrop = (e: DragEvent) => {
  e.preventDefault();
  isDragging.value = false;
  if (props.disabled || !e.dataTransfer) return;
  void processFiles(e.dataTransfer.files);
};

const removeFile = (name: string) => {
  const next = { ...props.files };
  delete next[name];
  emit('update:files', next);
};

const formatSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
};
</script>

<template>
  <div class="space-y-2 font-sans">
    <!-- Hidden native file input -->
    <input
      ref="fileInputRef"
      type="file"
      multiple
      accept=".conf,.data,.txt"
      class="sr-only"
      data-testid="rule-pack-file-input"
      :disabled="disabled"
      @change="onFileInputChange"
    />

    <!-- Empty state Dropzone -->
    <div
      v-if="filesList.length === 0"
      class="border border-dashed rounded-lg p-5 text-center transition-all cursor-pointer flex flex-col items-center justify-center gap-1.5"
      :class="[
        isDragging
          ? 'border-primary bg-primary/10 ring-1 ring-primary'
          : 'border-border bg-muted/20 hover:bg-muted/40 hover:border-primary/50 text-muted-foreground',
        disabled ? 'opacity-50 cursor-not-allowed' : ''
      ]"
      @dragover="onDragOver"
      @dragleave="onDragLeave"
      @drop="onDrop"
      @click="triggerBrowse"
    >
      <div class="p-2.5 rounded-full bg-muted border border-border text-primary">
        <UploadCloud class="w-5 h-5" />
      </div>
      <div class="text-xs">
        <span class="font-medium text-foreground">Click to upload</span>
        <span> or drag and drop include files</span>
      </div>
      <p class="text-xs text-muted-foreground">
        .conf, .data, or .txt files (preserved under <code class="font-mono text-foreground">packs/&lt;id&gt;/</code>)
      </p>
    </div>

    <!-- Staged Files List -->
    <div v-else class="space-y-2">
      <div class="flex items-center justify-between text-xs">
        <div class="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-muted-foreground">
          <span>Staged Include Files</span>
          <Badge variant="outline" class="font-mono text-xs">
            {{ filesList.length }}
          </Badge>
        </div>
        <div class="flex items-center gap-2">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            class="h-6 text-xs text-primary gap-1"
            :disabled="disabled"
            @click="triggerBrowse"
          >
            <Plus class="w-3 h-3" />
            <span>Add More</span>
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            class="h-6 text-xs text-destructive hover:text-destructive gap-1"
            :disabled="disabled"
            @click="emit('clear')"
          >
            <Trash2 class="w-3 h-3" />
            <span>Clear All</span>
          </Button>
        </div>
      </div>

      <div class="max-h-36 overflow-y-auto space-y-1 rounded-md border border-border bg-card p-2">
        <div
          v-for="file in filesList"
          :key="file.name"
          class="flex items-center justify-between px-2.5 py-1.5 rounded-md bg-muted/40 border border-border text-xs"
        >
          <div class="flex items-center gap-2 truncate">
            <FileText class="w-3.5 h-3.5 text-primary shrink-0" />
            <span class="font-mono font-medium text-foreground truncate max-w-xs" :title="file.name">
              {{ file.name }}
            </span>
            <span class="text-muted-foreground font-mono text-xs">
              ({{ file.lines }} lines · {{ formatSize(file.sizeBytes) }})
            </span>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            class="h-5 w-5 text-muted-foreground hover:text-destructive"
            :disabled="disabled"
            :aria-label="`Remove ${file.name}`"
            @click="removeFile(file.name)"
          >
            <X class="w-3 h-3" />
          </Button>
        </div>
      </div>
    </div>
  </div>
</template>
