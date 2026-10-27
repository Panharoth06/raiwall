<script setup lang="ts">
import { ref } from 'vue';
import { Eye, Monitor, Tablet, Smartphone, RefreshCw } from 'lucide-vue-next';

defineProps<{
  previewHtml: string;
}>();

const emit = defineEmits<{
  (e: 'refresh'): void;
}>();

const previewViewport = ref<'desktop' | 'tablet' | 'mobile'>('desktop');
</script>

<template>
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
          @click="emit('refresh')"
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
          class="w-full h-full border-none bg-preview"
          title="Response Template Preview"
        />
      </div>
    </div>
  </div>
</template>
