<script setup lang="ts">
import { computed } from 'vue';

/** Renders request/response text with the malicious token isolated and highlighted. */
const props = defineProps<{
  text: string;
  token?: string;
}>();

interface Segment {
  value: string;
  hit: boolean;
}

const segments = computed<Segment[]>(() => {
  const text = props.text ?? '';
  const token = (props.token ?? '').trim();
  if (!token || !text.includes(token)) {
    return [{ value: text, hit: false }];
  }
  const parts = text.split(token);
  return parts.flatMap((part, index) => {
    if (index === 0) return [{ value: part, hit: false }];
    return [
      { value: token, hit: true },
      { value: part, hit: false },
    ];
  });
});
</script>

<template>
  <pre class="p-3.5 bg-muted/60 border border-border rounded-lg overflow-x-auto max-h-56 text-foreground font-mono text-xs whitespace-pre-wrap break-all"><template
    v-for="(segment, index) in segments"
    :key="index"
  ><mark
    v-if="segment.hit"
    data-testid="matched-token"
    class="bg-threat/20 text-threat font-semibold px-0.5 rounded-sm"
  >{{ segment.value }}</mark><span v-else>{{ segment.value }}</span></template></pre>
</template>
