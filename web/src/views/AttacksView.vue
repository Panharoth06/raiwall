<script setup lang="ts">
import { useRouter } from '@/router';
import LiveInspector from '@/components/LiveInspector.vue';
import type { ExceptionDraft } from '@/types/telemetry';

const router = useRouter();

function handleCreateException(draft: ExceptionDraft) {
  const query = new URLSearchParams({
    create: 'true',
    host: draft.host || '*',
    path: draft.path || '/',
    method: draft.method || 'ALL',
    location: draft.location || 'query',
    param: draft.param || '*',
    rule_id: draft.rule_id || 'ALL',
  });
  router.push(`/exceptions?${query.toString()}`);
}
</script>

<template>
  <div class="h-full w-full flex flex-col">
    <LiveInspector @create-exception="handleCreateException" />
  </div>
</template>
