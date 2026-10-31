<script setup lang="ts">
import type { Component } from 'vue';

defineProps<{
  title: string;
  description?: string;
  icon?: Component;
}>();
</script>

<template>
  <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-border pb-4 shrink-0">
    <div class="min-w-0">
      <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
        <component :is="icon" v-if="icon" class="w-5 h-5 text-primary shrink-0" />
        <span class="truncate">{{ title }}</span>
      </h1>
      <p v-if="description" class="text-sm text-muted-foreground mt-1">
        {{ description }}
      </p>
    </div>
    <div v-if="$slots.actions" class="flex items-center gap-2 shrink-0">
      <slot name="actions" />
    </div>
  </div>
</template>
