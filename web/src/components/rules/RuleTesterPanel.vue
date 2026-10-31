<script setup lang="ts">
import { computed, ref } from 'vue';
import { AlertTriangle, FlaskConical, Play, RotateCcw, ShieldCheck } from 'lucide-vue-next';
import { api } from '@/api/client';
import type { RuleTestRequest, RuleTestResult } from '@/types/rules';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;

const method = ref<string>('GET');
const host = ref('');
const path = ref('/');
const query = ref('');
const clientIP = ref('');
const appID = ref('');
const headersText = ref('Accept: application/json');
const body = ref('');

const loading = ref(false);
const error = ref('');
const result = ref<RuleTestResult | null>(null);

const actionVariant = computed(() => {
  switch (result.value?.verdict.action) {
    case 'block':
      return 'threat';
    case 'audit':
      return 'info';
    case 'challenge':
      return 'warning';
    default:
      return 'success';
  }
});

const matchedRules = computed(() => result.value?.verdict.matched_rules ?? []);

function parseHeaders(raw: string): { headers: Record<string, string>; error?: string } {
  const headers: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf(':');
    if (idx <= 0) {
      return { headers, error: `Invalid header line: ${trimmed}` };
    }
    headers[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  }
  return { headers };
}

async function evaluate() {
  error.value = '';
  const parsed = parseHeaders(headersText.value);
  if (parsed.error) {
    error.value = parsed.error;
    return;
  }
  if (!path.value.startsWith('/')) {
    error.value = 'Path must start with /';
    return;
  }

  const payload: RuleTestRequest = {
    method: method.value,
    path: path.value,
    headers: parsed.headers,
  };
  if (host.value.trim()) payload.host = host.value.trim();
  if (query.value.trim()) payload.query = query.value.trim();
  if (clientIP.value.trim()) payload.client_ip = clientIP.value.trim();
  if (appID.value.trim()) payload.app_id = appID.value.trim();
  if (body.value) payload.body = body.value;

  loading.value = true;
  try {
    result.value = await api.testRule(payload);
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Evaluation request failed';
  } finally {
    loading.value = false;
  }
}

function reset() {
  method.value = 'GET';
  host.value = '';
  path.value = '/';
  query.value = '';
  clientIP.value = '';
  appID.value = '';
  headersText.value = 'Accept: application/json';
  body.value = '';
  result.value = null;
  error.value = '';
}

function severityVariant(severity?: string): 'threat' | 'warning' | 'info' | 'outline' {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
    case 'error':
      return 'threat';
    case 'warning':
    case 'notice':
      return 'warning';
    case 'info':
      return 'info';
    default:
      return 'outline';
  }
}
</script>

<template>
  <div class="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start">
    <!-- Probe form -->
    <Card>
      <CardHeader>
        <CardTitle class="flex items-center gap-2">
          <FlaskConical class="w-4 h-4 text-muted-foreground" />
          Request Probe
        </CardTitle>
        <CardDescription>
          Evaluate a synthetic request against the live semantic engine and OWASP CRS.
          No traffic reaches the upstream.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form class="space-y-4" @submit.prevent="evaluate">
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div class="space-y-1.5">
              <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Method</label>
              <Select v-model="method">
                <SelectTrigger aria-label="HTTP method" class="h-9 text-xs font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="m in METHODS" :key="m" :value="m" class="text-xs font-mono">
                    {{ m }}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="space-y-1.5 sm:col-span-2">
              <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Host</label>
              <Input v-model="host" aria-label="Host" placeholder="app.example.com (optional)" class="font-mono" />
            </div>
          </div>

          <div class="space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Path</label>
            <Input v-model="path" aria-label="Path" placeholder="/search" class="font-mono" />
          </div>

          <div class="space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Query String</label>
            <Input
              v-model="query"
              aria-label="Query string"
              placeholder="q=1' OR '1'='1"
              class="font-mono"
            />
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="space-y-1.5">
              <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Client IP</label>
              <Input v-model="clientIP" aria-label="Client IP" placeholder="203.0.113.10 (optional)" class="font-mono" />
            </div>
            <div class="space-y-1.5">
              <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">App ID</label>
              <Input v-model="appID" aria-label="Application ID" placeholder="optional" class="font-mono" />
            </div>
          </div>

          <div class="space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Headers (one per line)
            </label>
            <Textarea v-model="headersText" :rows="3" aria-label="Headers" class="text-xs" />
          </div>

          <div class="space-y-1.5">
            <label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Body</label>
            <Textarea v-model="body" :rows="4" aria-label="Body" placeholder="Request body (optional)" class="text-xs" />
          </div>

          <div class="flex items-center justify-end gap-2 pt-1">
            <Button type="button" variant="ghost" size="sm" :disabled="loading" @click="reset">
              <RotateCcw class="w-4 h-4 mr-1.5" />
              Reset
            </Button>
            <Button type="submit" size="sm" :disabled="loading">
              <Play class="w-4 h-4 mr-1.5" />
              {{ loading ? 'Evaluating...' : 'Evaluate Request' }}
            </Button>
          </div>
        </form>

        <div
          v-if="error"
          role="alert"
          class="mt-4 flex items-start gap-2 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-sm text-threat"
        >
          <AlertTriangle class="w-4 h-4 mt-0.5 shrink-0" />
          <span>{{ error }}</span>
        </div>
      </CardContent>
    </Card>

    <!-- Verdict -->
    <Card class="min-h-72">
      <CardHeader>
        <CardTitle>Verdict</CardTitle>
        <CardDescription>Engine decision, anomaly score, and contributing rules.</CardDescription>
      </CardHeader>
      <CardContent>
        <EmptyState
          v-if="!result && !loading"
          :icon="FlaskConical"
          title="No probe evaluated"
          description="Fill in a request and run the probe to see how the live policy would decide."
        />
        <div v-else-if="loading" class="space-y-3" aria-busy="true" aria-label="Evaluating request">
          <div class="h-9 w-32 rounded-md bg-muted animate-pulse" />
          <div class="h-4 w-64 rounded bg-muted animate-pulse" />
          <div class="h-24 w-full rounded-md bg-muted animate-pulse" />
        </div>
        <div v-else-if="result" class="space-y-4">
          <div class="flex flex-wrap items-center gap-2">
            <Badge :variant="actionVariant" class="uppercase">{{ result.verdict.action }}</Badge>
            <Badge v-if="result.verdict.engine" variant="outline" class="uppercase font-mono">
              {{ result.verdict.engine }}
            </Badge>
            <span v-if="result.verdict.rule_id" class="text-xs font-mono text-foreground">
              {{ result.verdict.rule_id }}
            </span>
            <span class="ml-auto text-xs font-mono tabular-nums text-muted-foreground">
              {{ result.duration_ms.toFixed(2) }} ms
            </span>
          </div>

          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div class="rounded-md border border-border bg-muted/40 px-3 py-2">
              <span class="block text-xs uppercase tracking-wider text-muted-foreground">Anomaly</span>
              <span class="text-sm font-mono tabular-nums text-foreground">
                {{ result.verdict.anomaly_score ?? 0 }}
              </span>
            </div>
            <div class="rounded-md border border-border bg-muted/40 px-3 py-2">
              <span class="block text-xs uppercase tracking-wider text-muted-foreground">Paranoia</span>
              <span class="text-sm font-mono tabular-nums text-foreground">
                PL{{ result.verdict.paranoia_level ?? 0 }}
              </span>
            </div>
            <div class="rounded-md border border-border bg-muted/40 px-3 py-2">
              <span class="block text-xs uppercase tracking-wider text-muted-foreground">Status</span>
              <span class="text-sm font-mono tabular-nums text-foreground">
                {{ result.verdict.status_code ?? '—' }}
              </span>
            </div>
            <div class="rounded-md border border-border bg-muted/40 px-3 py-2">
              <span class="block text-xs uppercase tracking-wider text-muted-foreground">Category</span>
              <span class="text-sm font-mono text-foreground truncate block">
                {{ result.verdict.attack_category || '—' }}
              </span>
            </div>
          </div>

          <p v-if="result.verdict.reason" class="text-sm text-muted-foreground leading-relaxed">
            {{ result.verdict.reason }}
          </p>

          <div v-if="matchedRules.length" class="space-y-2">
            <h4 class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Matched Rules
            </h4>
            <div class="rounded-md border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead class="w-24">Rule</TableHead>
                    <TableHead class="w-24">Severity</TableHead>
                    <TableHead>Message</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow v-for="(rule, index) in matchedRules" :key="`${rule.rule_id}-${index}`">
                    <TableCell class="font-mono text-xs">{{ rule.rule_id }}</TableCell>
                    <TableCell>
                      <Badge :variant="severityVariant(rule.severity)" class="uppercase">
                        {{ rule.severity || 'unknown' }}
                      </Badge>
                    </TableCell>
                    <TableCell class="text-xs text-muted-foreground">
                      {{ rule.message || '—' }}
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </div>
          </div>

          <div
            v-if="result.verdict.action === 'allow'"
            class="flex items-center gap-2 text-sm text-success"
          >
            <ShieldCheck class="w-4 h-4" />
            Request allowed by the current policy.
          </div>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
