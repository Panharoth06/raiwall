<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { X, FileCode, ExternalLink, ClipboardCopy, ShieldAlert, CheckCircle2 } from 'lucide-vue-next';
import type { ForensicEvent, IPGroupOption, CurlState } from '@/types/telemetry';
import HighlightedCode from './HighlightedCode.vue';
import IpGroupPicker from './IpGroupPicker.vue';

/** Full-height forensic drawer for a single captured event. */
const props = defineProps<{
  event: ForensicEvent;
  curlState?: CurlState;
  groups?: IPGroupOption[];
  groupStatus?: string;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'create-exception'): void;
  (e: 'copy-curl', event: ForensicEvent): void;
  (e: 'add-to-ipgroup', payload: { event: ForensicEvent; groupId: string }): void;
}>();

const tab = ref<'request' | 'response'>('request');
const encoding = ref<'utf-8' | 'gbk'>('utf-8');

watch(
  () => props.event?.event_id,
  () => {
    tab.value = 'request';
    encoding.value = 'utf-8';
  }
);

const isBlocked = computed(() => props.event.action !== 'allow');

const ja4Link = computed(() =>
  props.event.ja4 ? `https://ja4db.com/?q=${encodeURIComponent(props.event.ja4)}` : ''
);

const requestText = computed(() => {
  const ev = props.event;
  if (ev.truncated_payload && ev.truncated_payload.trim() !== '') {
    return convertCharset(ev.truncated_payload, encoding.value);
  }
  if (ev.path && ev.path.includes('?')) {
    const qs = ev.path.slice(ev.path.indexOf('?') + 1);
    try {
      return convertCharset(decodeURIComponent(qs), encoding.value);
    } catch {
      return qs;
    }
  }
  return '(No payload or query parameters)';
});

const responseBodyText = computed(() => decodeBody(props.event.response_body ?? '', encoding.value));

const responseHeaders = computed(() => Object.entries(props.event.response_headers ?? {}));

const curlLabel = computed(() => {
  switch (props.curlState) {
    case 'loading':
      return 'Generating...';
    case 'copied':
      return 'Copied';
    case 'error':
      return 'Copy failed';
    default:
      return 'Copy as cURL';
  }
});

function getActionBadgeClass(action: string): string {
  switch (action) {
    case 'allow':
      return 'bg-success/10 text-success border-success/30';
    case 'block':
      return 'bg-threat/10 text-threat border-threat/30';
    case 'challenge':
      return 'bg-warning/10 text-warning border-warning/30';
    case 'ban':
      return 'bg-threat/20 text-threat border-threat/40';
    default:
      return 'bg-muted text-muted-foreground border-border';
  }
}

function formatLatency(durNs: number): string {
  const ms = durNs / 1000000;
  return ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : `${ms.toFixed(1)}ms`;
}

/** Decode a captured byte body. Go marshals []byte as base64. */
function decodeBody(raw: string, charset: 'utf-8' | 'gbk'): string {
  if (!raw) return '';
  try {
    const binary = atob(raw);
    return new TextDecoder(charset).decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
  } catch {
    return convertCharset(raw, charset);
  }
}

/** Re-interpret a text body under the selected charset without assuming base64 encoding. */
function convertCharset(text: string, charset: 'utf-8' | 'gbk'): string {
  if (!text || charset === 'utf-8') return text;
  try {
    return new TextDecoder('gbk').decode(Uint8Array.from(text, (c) => c.charCodeAt(0)));
  } catch {
    return text;
  }
}
</script>

<template>
  <div
    data-testid="forensic-modal"
    class="fixed inset-0 z-50 flex justify-end bg-black/50"
    @click.self="emit('close')"
  >
    <aside class="w-full max-w-2xl h-full flex flex-col bg-popover border-l border-border text-popover-foreground font-sans">
      <!-- Header -->
      <header class="px-5 py-4 border-b border-border bg-card">
        <div class="flex items-start justify-between gap-3">
          <div class="flex items-center gap-3 min-w-0">
            <div class="p-2 rounded-lg bg-muted border border-border text-muted-foreground">
              <FileCode class="w-4 h-4" />
            </div>
            <div class="min-w-0">
              <h3 class="text-sm font-bold text-foreground flex items-center gap-2">
                <span>{{ isBlocked ? 'Forensic Incident Context' : 'Traffic Telemetry Context' }}</span>
                <span
                  class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase border"
                  :class="getActionBadgeClass(event.action)"
                >
                  {{ event.action }}
                </span>
              </h3>
              <p class="text-[11px] text-muted-foreground font-mono mt-0.5 truncate">
                {{ event.event_id }} • {{ new Date(event.timestamp).toISOString() }}
              </p>
            </div>
          </div>
          <button
            type="button"
            data-testid="modal-close-btn"
            class="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors cursor-pointer"
            @click="emit('close')"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </header>

      <!-- Body -->
      <div class="flex-1 overflow-y-auto p-5 space-y-4 text-xs font-mono">
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <div class="p-2.5 bg-muted/40 border border-border rounded-lg">
            <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Target Host</span>
            <span class="text-foreground truncate block">{{ event.host }}</span>
          </div>
          <div class="p-2.5 bg-muted/40 border border-border rounded-lg">
            <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Client IP</span>
            <span class="text-foreground block">{{ event.client_ip }}</span>
          </div>
          <div class="p-2.5 bg-muted/40 border border-border rounded-lg">
            <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Rule ID</span>
            <span class="text-warning font-semibold block truncate">{{ event.rule_id || 'NONE' }}</span>
          </div>
          <div class="p-2.5 bg-muted/40 border border-border rounded-lg">
            <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Latency</span>
            <span class="text-foreground block">{{ formatLatency(event.latency) }}</span>
          </div>
        </div>

        <!-- Detection diagnostics -->
        <div class="flex flex-wrap items-center gap-2 text-[11px]">
          <span
            data-testid="payload-location"
            class="px-2 py-0.5 rounded border border-border bg-muted text-foreground uppercase tracking-wide"
          >
            {{ event.payload_location || 'UNKNOWN' }}
          </span>
          <span v-if="event.attack_category" class="px-2 py-0.5 rounded border border-threat/30 bg-threat/10 text-threat">
            {{ event.attack_category }}
          </span>
          <a
            v-if="event.ja4"
            data-testid="ja4-link"
            :href="ja4Link"
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center gap-1 text-info hover:underline"
          >
            JA4 {{ event.ja4 }}
            <ExternalLink class="w-3 h-3" />
          </a>
        </div>

        <div v-if="event.matched_token">
          <h4 class="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
            Matched Malicious Token
          </h4>
          <HighlightedCode :text="event.matched_token" :token="event.matched_token" />
        </div>

        <!-- Request / Response viewer -->
        <div class="border border-border rounded-lg overflow-hidden">
          <div class="flex items-center justify-between px-3 py-2 bg-muted/40 border-b border-border">
            <div class="flex items-center gap-1">
              <button
                type="button"
                data-testid="drawer-tab-request"
                class="px-2.5 py-1 rounded text-[11px] font-semibold uppercase tracking-wide transition-colors cursor-pointer"
                :class="tab === 'request' ? 'bg-background text-foreground border border-border' : 'text-muted-foreground hover:text-foreground'"
                @click="tab = 'request'"
              >
                Request
              </button>
              <button
                type="button"
                data-testid="drawer-tab-response"
                class="px-2.5 py-1 rounded text-[11px] font-semibold uppercase tracking-wide transition-colors cursor-pointer"
                :class="tab === 'response' ? 'bg-background text-foreground border border-border' : 'text-muted-foreground hover:text-foreground'"
                @click="tab = 'response'"
              >
                Response
              </button>
            </div>
            <select
              v-if="tab === 'request'"
              v-model="encoding"
              data-testid="encoding-select"
              class="h-7 px-1.5 text-[11px] bg-background border border-input rounded text-foreground"
            >
              <option value="utf-8">UTF-8</option>
              <option value="gbk">GBK</option>
            </select>
            <span v-else class="text-[11px] text-muted-foreground font-mono">HTTP {{ event.status_code }}</span>
          </div>

          <div v-if="tab === 'request'" class="p-3 space-y-3">
            <div>
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">
                {{ event.method }} {{ event.path }}
              </span>
              <pre class="p-3 bg-muted/60 border border-border rounded-lg overflow-x-auto max-h-40 text-[11px] text-foreground whitespace-pre-wrap break-all">{{ JSON.stringify(event.headers || {}, null, 2) }}</pre>
            </div>
            <div>
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Body / Parameters</span>
              <HighlightedCode :text="requestText" :token="event.matched_token" />
            </div>
          </div>

          <div v-else class="p-3 space-y-3">
            <div v-if="responseHeaders.length > 0">
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Response Headers</span>
              <pre class="p-3 bg-muted/60 border border-border rounded-lg overflow-x-auto max-h-32 text-[11px] text-foreground whitespace-pre-wrap break-all">{{ responseHeaders.map(([key, values]) => `${key}: ${values.join(', ')}`).join('\n') }}</pre>
            </div>
            <div>
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Response Body</span>
              <HighlightedCode :text="responseBodyText || '(No response body captured)'" />
            </div>
          </div>
        </div>

        <!-- Containment -->
        <div class="flex flex-wrap items-center gap-2">
          <IpGroupPicker
            :groups="groups || []"
            :disabled="!event.client_ip"
            :status="groupStatus"
            @add="(groupId) => emit('add-to-ipgroup', { event, groupId })"
          />
        </div>
      </div>

      <!-- Footer actions -->
      <footer class="flex items-center justify-between gap-3 px-5 py-3 border-t border-border bg-card">
        <span class="text-[11px] text-muted-foreground flex items-center gap-1.5">
          <CheckCircle2 v-if="!isBlocked" class="w-3.5 h-3.5 text-success" />
          <ShieldAlert v-else class="w-3.5 h-3.5 text-threat" />
          {{ isBlocked ? 'Verified attack signature captured for replay' : 'Benign request; no exception required' }}
        </span>
        <div class="flex items-center gap-2">
          <button
            type="button"
            data-testid="copy-curl-btn"
            :disabled="curlState === 'loading'"
            class="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-foreground bg-muted hover:bg-muted/80 border border-border rounded-lg transition-colors disabled:opacity-50 cursor-pointer"
            @click="emit('copy-curl', event)"
          >
            <ClipboardCopy class="w-3.5 h-3.5" />
            {{ curlLabel }}
          </button>
          <button
            v-if="isBlocked"
            type="button"
            data-testid="modal-create-exception-btn"
            class="px-3 py-1.5 text-xs font-semibold text-primary-foreground bg-primary hover:bg-primary/90 rounded-lg transition-colors cursor-pointer"
            @click="emit('create-exception')"
          >
            Create Exception
          </button>
        </div>
      </footer>
    </aside>
  </div>
</template>
