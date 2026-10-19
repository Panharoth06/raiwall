<script setup lang="ts">
import type { ConfigDiffItem } from '@/api/client';
import { PlusCircle, Edit3, Trash2, CheckCircle2 } from 'lucide-vue-next';

defineProps<{
  diffs: ConfigDiffItem[];
}>();
</script>

<template>
  <div class="space-y-3">
    <div v-if="diffs.length === 0" class="p-8 bg-slate-900 border border-slate-800 rounded-xl text-center space-y-2">
      <CheckCircle2 class="w-10 h-10 text-emerald-400 mx-auto" />
      <h3 class="text-sm font-semibold text-slate-200">No pending staged changes</h3>
      <p class="text-xs text-slate-500 max-w-sm mx-auto">
        Your active configuration is up to date with the database. Modify sites, rules, or policies to stage new changes.
      </p>
    </div>

    <div v-else class="space-y-2">
      <div
        v-for="(item, idx) in diffs"
        :key="idx"
        class="p-4 bg-slate-900 border rounded-xl flex items-start justify-between text-xs transition-colors"
        :class="{
          'border-emerald-500/30 bg-emerald-500/5': item.action === 'added',
          'border-amber-500/30 bg-amber-500/5': item.action === 'modified',
          'border-rose-500/30 bg-rose-500/5': item.action === 'deleted',
        }"
      >
        <div class="flex items-start space-x-3">
          <div class="mt-0.5">
            <PlusCircle v-if="item.action === 'added'" class="w-4 h-4 text-emerald-400" />
            <Edit3 v-else-if="item.action === 'modified'" class="w-4 h-4 text-amber-400" />
            <Trash2 v-else class="w-4 h-4 text-rose-400" />
          </div>

          <div>
            <div class="flex items-center space-x-2">
              <span class="font-semibold text-slate-200 text-sm">{{ item.name }}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-slate-800 text-slate-400">
                {{ item.type }}
              </span>
              <span
                class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
                :class="{
                  'bg-emerald-500/20 text-emerald-400': item.action === 'added',
                  'bg-amber-500/20 text-amber-400': item.action === 'modified',
                  'bg-rose-500/20 text-rose-400': item.action === 'deleted',
                }"
              >
                {{ item.action }}
              </span>
            </div>
            <p class="text-xs text-slate-400 mt-1 font-mono">
              {{ item.details }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
