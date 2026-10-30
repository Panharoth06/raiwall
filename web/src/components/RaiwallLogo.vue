<script setup lang="ts">
withDefaults(
  defineProps<{
    size?: number | string;
    showText?: boolean;
    className?: string;
  }>(),
  {
    size: 32,
    showText: false,
    className: '',
  }
);
</script>

<template>
  <div class="inline-flex items-center gap-2.5 select-none" :class="className">
    <img
      src="/raiwall-logo.png"
      alt="Raiwall Logo"
      :style="{ width: typeof size === 'number' ? `${size}px` : size, height: typeof size === 'number' ? `${size}px` : size }"
      class="object-contain flex-shrink-0"
      style="image-rendering: -webkit-optimize-contrast;"
    />

    <div v-if="showText" class="flex flex-col justify-center">
      <span class="font-bold text-foreground text-base tracking-tight leading-none">Raiwall</span>
    </div>
  </div>
</template>
