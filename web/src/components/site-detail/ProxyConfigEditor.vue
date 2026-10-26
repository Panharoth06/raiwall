<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { api, type Site, type ProxySettings } from '@/api/client';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from '@/components/ui/select';
import { Loader2, RotateCcw, Sliders } from 'lucide-vue-next';

const props = defineProps<{ site: Site }>();

const IP_SOURCES = [
  { value: 'socket', label: 'TCP socket (direct)' },
  { value: 'xff', label: 'X-Forwarded-For header' },
  { value: 'realip', label: 'X-Real-IP header' },
];

const draft = ref<ProxySettings>({});
const saving = ref(false);
const error = ref('');

const readFromSite = (): ProxySettings => ({
  client_ip_source: props.site.proxy_settings?.client_ip_source || 'socket',
  rewrite_xff: !!props.site.proxy_settings?.rewrite_xff,
  hsts: !!props.site.proxy_settings?.hsts,
  enable_sse: !!props.site.proxy_settings?.enable_sse,
  enable_compression: !!props.site.proxy_settings?.enable_compression,
  enable_ipv6: !!props.site.proxy_settings?.enable_ipv6,
  redirect_http: !!props.site.proxy_settings?.redirect_http,
});

watch(() => props.site.id, () => {
  draft.value = readFromSite();
}, { immediate: true });

const dirty = computed(() => JSON.stringify(draft.value) !== JSON.stringify(readFromSite()));

const apply = async () => {
  saving.value = true;
  error.value = '';
  try {
    await api.updateSite(props.site.id, { proxy_settings: { ...draft.value } });
    props.site.proxy_settings = { ...draft.value };
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Apply failed';
    draft.value = readFromSite();
  } finally {
    saving.value = false;
  }
};

const discard = () => {
  draft.value = readFromSite();
  error.value = '';
};

const TOGGLES: { key: keyof ProxySettings; label: string; hint: string }[] = [
  { key: 'rewrite_xff', label: 'Rewrite X-Forwarded-For', hint: 'Strip untrusted outer client headers and pin the resolved client IP' },
  { key: 'hsts', label: 'HSTS Injection', hint: 'strict-transport-security on HTTPS responses (1 year, preload)' },
  { key: 'enable_sse', label: 'SSE / LLM Streaming', hint: 'Disable buffering for text/event-stream responses' },
  { key: 'enable_compression', label: 'Upstream Compression', hint: 'Pass client Accept-Encoding through (off keeps bodies inspectable)' },
  { key: 'enable_ipv6', label: 'IPv6 Listening', hint: 'Dual-stack socket bind preference for this site' },
  { key: 'redirect_http', label: 'HTTP → HTTPS Redirect', hint: '301 permanent redirect of plaintext traffic' },
];
</script>

<template>
  <div class="space-y-3" data-testid="proxy-editor">
    <div class="flex items-center justify-between">
      <span class="text-xs text-muted-foreground">Granular proxy tuning — changes apply on the next config snapshot</span>
      <div class="flex items-center gap-1.5">
        <Button variant="ghost" size="sm" class="h-7 px-2" :disabled="!dirty || saving" data-testid="proxy-discard" @click="discard">
          <RotateCcw class="w-3.5 h-3.5" />
          Discard
        </Button>
        <Button size="sm" class="h-7" :disabled="!dirty || saving" data-testid="proxy-apply" @click="apply">
          <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
          <Sliders v-else class="w-3.5 h-3.5" />
          Apply
        </Button>
      </div>
    </div>

    <p v-if="error" class="text-xs text-destructive" data-testid="proxy-error">{{ error }}</p>

    <div class="border border-border rounded-lg divide-y divide-border bg-background">
      <div class="flex items-center justify-between px-3 py-2.5" data-testid="proxy-client-ip">
        <div class="min-w-0 pr-3">
          <p class="text-xs font-medium">Client IP Source</p>
          <p class="text-xs text-muted-foreground mt-0.5">Header the gateway trusts for the real client address</p>
        </div>
        <Select v-model="draft.client_ip_source">
          <SelectTrigger class="h-7 w-48 text-xs" data-testid="proxy-client-ip-select">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem v-for="s in IP_SOURCES" :key="s.value" :value="s.value">{{ s.label }}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div
        v-for="toggle in TOGGLES"
        :key="toggle.key"
        class="flex items-center justify-between px-3 py-2.5"
        :data-testid="`proxy-${toggle.key.replace(/_/g, '-')}`"
      >
        <div class="min-w-0 pr-3">
          <p class="text-xs font-medium">{{ toggle.label }}</p>
          <p class="text-xs text-muted-foreground mt-0.5">{{ toggle.hint }}</p>
        </div>
        <Switch
          :model-value="!!draft[toggle.key]"
          @update:model-value="(v: boolean) => (draft[toggle.key] = v)"
          :data-testid="`proxy-toggle-${toggle.key}`"
        />
      </div>
    </div>
  </div>
</template>
