<script setup lang="ts">
import { ref } from 'vue';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Code, Palette, Copy, Check } from 'lucide-vue-next';

interface Props {
  contentHtml: string;
  customCss: string;
  brandName: string;
  logoUrl: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'update:contentHtml', val: string): void;
  (e: 'update:customCss', val: string): void;
  (e: 'update:brandName', val: string): void;
  (e: 'update:logoUrl', val: string): void;
}>();

const activeTab = ref<'html' | 'css'>('html');
const copiedTag = ref<string | null>(null);

const availableTags = [
  { tag: '{{.EventID}}', desc: 'UUID forensic tracking event' },
  { tag: '{{.ClientIP}}', desc: 'Normalized client IPv4/IPv6' },
  { tag: '{{.Timestamp}}', desc: 'RFC3339 UTC block time' },
  { tag: '{{.Host}}', desc: 'Protected domain host' },
  { tag: '{{.Path}}', desc: 'Blocked request URI path' },
  { tag: '{{.BrandName}}', desc: 'Configured enterprise name' },
  { tag: '{{.StatusCode}}', desc: 'HTTP numeric status' },
  { tag: '{{.StatusText}}', desc: 'Standard status string' },
];

const copyTag = (tag: string) => {
  navigator.clipboard?.writeText(tag);
  copiedTag.value = tag;
  setTimeout(() => {
    if (copiedTag.value === tag) copiedTag.value = null;
  }, 1800);
};

const handleInsertTag = (tag: string) => {
  if (activeTab.value === 'html') {
    emit('update:contentHtml', props.contentHtml + ' ' + tag);
  }
};
</script>

<template>
  <div class="flex flex-col h-full space-y-4">
    <!-- Brand and Logo metadata fields -->
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 bg-muted/40 rounded-lg border border-border">
      <div class="space-y-1">
        <label class="text-xs font-medium text-muted-foreground">Brand Name</label>
        <Input
          :model-value="brandName"
          placeholder="e.g. Raiwall Security"
          class="h-8 text-xs bg-background"
          @update:model-value="emit('update:brandName', $event as string)"
        />
      </div>
      <div class="space-y-1">
        <label class="text-xs font-medium text-muted-foreground">Logo URL (Optional)</label>
        <Input
          :model-value="logoUrl"
          placeholder="https://example.com/logo.svg"
          class="h-8 text-xs bg-background font-mono"
          @update:model-value="emit('update:logoUrl', $event as string)"
        />
      </div>
    </div>

    <!-- Available Variables bar -->
    <div class="space-y-1.5">
      <div class="flex items-center justify-between text-xs text-muted-foreground px-0.5">
        <span>Template Placeholders (Click to insert or copy)</span>
        <span class="text-[11px] font-mono opacity-80">{{ availableTags.length }} variables</span>
      </div>
      <div class="flex flex-wrap gap-1.5">
        <button
          v-for="item in availableTags"
          :key="item.tag"
          type="button"
          class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-muted border border-border text-foreground hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer select-none"
          :title="item.desc"
          @click="handleInsertTag(item.tag)"
          @dblclick.stop="copyTag(item.tag)"
        >
          <span>{{ item.tag }}</span>
          <component :is="copiedTag === item.tag ? Check : Copy" class="w-2.5 h-2.5 text-muted-foreground" />
        </button>
      </div>
    </div>

    <!-- Code Editor Controls & Area -->
    <div class="flex flex-col flex-1 min-h-[420px] border border-border rounded-lg overflow-hidden bg-background">
      <!-- Editor Mode Tabs -->
      <div class="flex items-center justify-between px-3 py-2 border-b border-border bg-muted/30">
        <div class="flex items-center gap-1.5">
          <Button
            size="sm"
            :variant="activeTab === 'html' ? 'default' : 'ghost'"
            class="h-7 text-xs px-2.5 gap-1.5"
            @click="activeTab = 'html'"
          >
            <Code class="w-3.5 h-3.5" />
            HTML Body
          </Button>
          <Button
            size="sm"
            :variant="activeTab === 'css' ? 'default' : 'ghost'"
            class="h-7 text-xs px-2.5 gap-1.5"
            @click="activeTab = 'css'"
          >
            <Palette class="w-3.5 h-3.5" />
            Custom CSS
          </Button>
        </div>
        <span class="text-[11px] font-mono text-muted-foreground">
          {{ activeTab === 'html' ? 'HTML5 Document' : 'CSS Variables & Rules' }}
        </span>
      </div>

      <!-- Editor Textarea -->
      <div class="flex-1 relative min-h-[380px]">
        <textarea
          v-if="activeTab === 'html'"
          :value="contentHtml"
          spellcheck="false"
          placeholder="<!DOCTYPE html>..."
          class="absolute inset-0 w-full h-full p-3 font-mono text-xs leading-relaxed bg-background text-foreground resize-none border-none focus:outline-none focus:ring-0 overflow-auto"
          @input="emit('update:contentHtml', ($event.target as HTMLTextAreaElement).value)"
        />
        <textarea
          v-else
          :value="customCss"
          spellcheck="false"
          placeholder=":root { ... }"
          class="absolute inset-0 w-full h-full p-3 font-mono text-xs leading-relaxed bg-background text-foreground resize-none border-none focus:outline-none focus:ring-0 overflow-auto"
          @input="emit('update:customCss', ($event.target as HTMLTextAreaElement).value)"
        />
      </div>
    </div>
  </div>
</template>
