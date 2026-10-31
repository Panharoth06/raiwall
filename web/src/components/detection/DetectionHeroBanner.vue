<script setup lang="ts">
import { computed, type Component } from 'vue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Sparkles, X } from 'lucide-vue-next';

export interface HeroHighlight {
  label: string;
  text: string;
}

const props = withDefaults(
  defineProps<{
    storageKey: string;
    title: string;
    badge?: string;
    description: string;
    icon: Component;
    highlights?: HeroHighlight[];
    open?: boolean;
  }>(),
  {
    badge: 'FEATURE GUIDE',
    highlights: () => [],
    open: true,
  }
);

const emit = defineEmits<{
  (e: 'update:open', value: boolean): void;
  (e: 'dismiss'): void;
  (e: 'close'): void;
}>();

const storageKeyName = computed(() => `raiwall_hero_dismissed_${props.storageKey}`);

const handleClose = () => {
  emit('update:open', false);
  emit('close');
};

const handleDismiss = () => {
  if (typeof localStorage !== 'undefined') {
    try {
      localStorage.setItem(storageKeyName.value, 'true');
    } catch {
      // safe fallback
    }
  }
  emit('update:open', false);
  emit('dismiss');
};
</script>

<template>
  <!-- Smooth Grid-Based Height & Opacity Collapse/Expand Animation -->
  <div
    class="grid transition-[grid-template-rows,opacity] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] font-sans"
    :class="open ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0 pointer-events-none'"
    :data-testid="`hero-banner-${storageKey}`"
  >
    <div class="min-h-0 overflow-hidden">
      <section
        class="relative overflow-hidden rounded-xl border border-border bg-card p-5 sm:p-6 shadow-sm mb-1"
        role="region"
        :aria-label="title"
      >
        <!-- Background Watermark Graphic (Low-opacity with smooth linear gradient mask) -->
        <div
          class="absolute -right-4 -bottom-6 top-0 w-1/2 flex items-center justify-end pointer-events-none select-none text-primary/[0.08] dark:text-primary/[0.05] [mask-image:linear-gradient(to_left,rgba(0,0,0,1)_30%,transparent_100%)] overflow-hidden"
          aria-hidden="true"
        >
          <component
            :is="icon"
            class="w-48 h-48 sm:w-60 sm:h-60 stroke-[1.25] translate-x-4 translate-y-4 shrink-0"
          />
        </div>

        <!-- Foreground Content Layout -->
        <div class="relative z-10 max-w-3xl space-y-3.5 pr-6 sm:pr-8">
          <!-- Badge & Close Trigger -->
          <div class="flex items-center justify-between gap-2">
            <Badge
              variant="outline"
              class="font-mono text-xs uppercase tracking-wider bg-primary/10 text-primary border-primary/30"
            >
              <Sparkles class="w-3 h-3 mr-1 inline" />
              {{ badge }}
            </Badge>

            <Button
              variant="ghost"
              size="icon"
              class="h-7 w-7 text-muted-foreground hover:text-foreground shrink-0 rounded-md"
              title="Close guide for now"
              :data-testid="`hero-close-${storageKey}`"
              @click="handleClose"
            >
              <X class="w-3.5 h-3.5" />
            </Button>
          </div>

          <!-- Main Title & Feature Purpose -->
          <div class="space-y-1.5">
            <h2 class="text-base sm:text-lg font-bold tracking-tight text-foreground flex items-center gap-2">
              <component :is="icon" class="w-5 h-5 text-primary shrink-0 sm:hidden" />
              <span>{{ title }}</span>
            </h2>
            <p class="text-xs sm:text-sm text-muted-foreground leading-relaxed">
              {{ description }}
            </p>
          </div>

          <!-- Highlight Takeaway Chips (Optional) -->
          <div
            v-if="highlights && highlights.length > 0"
            class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 pt-1"
          >
            <div
              v-for="(item, idx) in highlights"
              :key="idx"
              class="rounded-lg border border-border/70 bg-muted/30 px-3 py-2 text-xs flex flex-col justify-center"
            >
              <span class="font-semibold text-foreground">{{ item.label }}</span>
              <span class="text-muted-foreground mt-0.5 leading-snug">{{ item.text }}</span>
            </div>
          </div>

          <!-- Controls: Do not show again button -->
          <div class="flex items-center gap-3 pt-1">
            <Button
              variant="secondary"
              size="sm"
              class="h-7 px-2.5 text-xs text-muted-foreground hover:text-foreground border border-border"
              :data-testid="`hero-dismiss-${storageKey}`"
              @click="handleDismiss"
            >
              <span>Do not show again</span>
            </Button>
            <slot name="extra-actions" />
          </div>
        </div>
      </section>
    </div>
  </div>
</template>
