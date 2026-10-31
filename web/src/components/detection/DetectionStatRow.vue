<script setup lang="ts">
export interface DetectionStat {
  label: string;
  value: string | number;
  hint?: string;
  tone?: 'default' | 'threat' | 'success' | 'warning' | 'muted';
}

defineProps<{
  items: DetectionStat[];
}>();

const toneClass = (tone: DetectionStat['tone']) => {
  switch (tone) {
    case 'threat':
      return 'text-threat';
    case 'success':
      return 'text-success';
    case 'warning':
      return 'text-warning';
    case 'muted':
      return 'text-muted-foreground';
    default:
      return 'text-foreground';
  }
};
</script>

<template>
  <div class="flex flex-wrap items-center gap-x-7 gap-y-2 rounded-lg border border-border bg-card px-3 py-2">
    <div v-for="item in items" :key="item.label" class="flex items-baseline gap-2">
      <span class="text-xs uppercase tracking-wider text-muted-foreground">{{ item.label }}</span>
      <span class="font-mono tabular-nums text-sm font-semibold" :class="toneClass(item.tone)">
        {{ item.value }}
      </span>
      <span v-if="item.hint" class="text-xs text-muted-foreground">{{ item.hint }}</span>
    </div>
  </div>
</template>
