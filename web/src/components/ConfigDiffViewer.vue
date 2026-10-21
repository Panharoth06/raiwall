<script setup lang="ts">
import type { ConfigDiffItem } from '@/api/client';
import { PlusCircle, Edit3, Trash2, CheckCircle2 } from 'lucide-vue-next';

defineProps<{
  diffs: ConfigDiffItem[];
}>();
</script>

<template>
  <div class="space-y-3 font-sans">
    <div v-if="diffs.length === 0" class="p-8 bg-card border border-border rounded-xl text-center space-y-2">
      <CheckCircle2 class="w-10 h-10 text-muted-foreground mx-auto" />
      <h3 class="text-sm font-semibold text-foreground">No pending staged changes</h3>
      <p class="text-xs text-muted-foreground max-w-sm mx-auto">
        Your active configuration is up to date with the database. Modify sites, rules, or policies to stage new changes.
      </p>
    </div>

    <div v-else class="space-y-2">
      <div
        v-for="(item, idx) in diffs"
        :key="idx"
        class="p-4 bg-card border rounded-xl flex items-start justify-between text-xs transition-colors"
        :class="{
          'border-success/30 bg-success/5': item.action === 'added',
          'border-warning/30 bg-warning/5': item.action === 'modified',
          'border-threat/30 bg-threat/5': item.action === 'deleted',
        }"
      >
        <div class="flex items-start space-x-3">
          <div class="mt-0.5">
            <PlusCircle v-if="item.action === 'added'" class="w-4 h-4 text-success" />
            <Edit3 v-else-if="item.action === 'modified'" class="w-4 h-4 text-warning" />
            <Trash2 v-else class="w-4 h-4 text-threat" />
          </div>

          <div>
            <div class="flex items-center space-x-2">
              <span class="font-semibold text-foreground text-sm">{{ item.name }}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-muted text-muted-foreground border border-border">
                {{ item.type }}
              </span>
              <span
                class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
                :class="{
                  'bg-success/20 text-success': item.action === 'added',
                  'bg-warning/20 text-warning': item.action === 'modified',
                  'bg-threat/20 text-threat': item.action === 'deleted',
                }"
              >
                {{ item.action }}
              </span>
            </div>
            <p class="text-xs text-muted-foreground mt-1 font-mono">
              {{ item.details }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
