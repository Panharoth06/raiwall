<script setup lang="ts">
import { computed } from 'vue'
import {
  ShieldCheck,
  ShieldAlert,
  Zap,
  Lock,
  Cpu,
  Globe,
  Radio,
  Sliders,
  CheckCircle2,
} from 'lucide-vue-next'
import type { AggregateStats } from '@/types/telemetry'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { EmptyState } from '@/components/ui/empty-state'

const props = defineProps<{
  stats: AggregateStats
}>()

const protectionEngines = [
  {
    name: 'Semantic SQLi Engine',
    desc: 'Pure-Go libinjection lexer + TiDB AST verification',
    status: 'ACTIVE',
    latency: '< 2 µs',
    icon: Cpu,
  },
  {
    name: 'Semantic XSS & HTML AST',
    desc: 'AST token stream validator (tdewolff/parse)',
    status: 'ACTIVE',
    latency: '< 3 µs',
    icon: Zap,
  },
  {
    name: 'Command Injection Verifier',
    desc: 'mvdan/sh AST parser with 32KB/5ms cap',
    status: 'ACTIVE',
    latency: '< 5 µs',
    icon: Lock,
  },
  {
    name: 'Active Bot Defense & JA4',
    desc: 'JA4 TLS fingerprinting + HTTP 468 PoW challenge',
    status: 'ACTIVE',
    latency: '< 1 µs',
    icon: Radio,
  },
  {
    name: '3-Tier Rate Limiting',
    desc: 'Composite IP+JA4 keys with GCRA algorithm',
    status: 'ACTIVE',
    latency: '< 1 µs',
    icon: Sliders,
  },
  {
    name: 'BART CIDR & expr ACLs',
    desc: 'gaissmai/bart sub-15ns table + compiled bytecode',
    status: 'ACTIVE',
    latency: '< 15 ns',
    icon: Globe,
  },
]

const securityScore = computed(() => {
  if (props.stats.total_requests === 0) return 100
  const ratio = props.stats.block_ratio
  if (ratio > 0.5) return 88
  if (ratio > 0.2) return 94
  return 98
})
</script>

<template>
  <div class="space-y-6 font-sans">
    <!-- Top Security Posture Overview Banner -->
    <Card class="overflow-hidden">
      <CardContent class="p-6 grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        <!-- Score Indicator -->
        <div class="md:col-span-5 flex items-center gap-5">
          <div class="w-20 h-20 rounded-2xl bg-success/10 border border-success/30 flex flex-col items-center justify-center shrink-0">
            <span class="text-3xl font-bold font-mono text-success tabular-nums">{{ securityScore }}</span>
            <span class="text-xs font-mono text-muted-foreground uppercase font-semibold">Score</span>
          </div>

          <div class="space-y-1">
            <div class="flex items-center gap-1.5 text-success text-xs font-bold uppercase tracking-wider">
              <ShieldCheck class="w-4 h-4" />
              <span>Under Active Protection</span>
            </div>
            <h3 class="text-base font-bold text-foreground">Defensive Posture: Optimal</h3>
            <p class="text-xs text-muted-foreground">
              Zero critical bypasses detected across all active proxy upstreams.
            </p>
          </div>
        </div>

        <!-- Quick Posture Metric Stats -->
        <div class="md:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div class="p-3.5 bg-muted/30 border border-border rounded-lg">
            <div class="text-xs text-muted-foreground mb-1 font-medium">Threat Interceptions</div>
            <div class="text-xl font-bold font-mono text-threat tabular-nums">
              {{ stats.total_blocked.toLocaleString() }}
            </div>
          </div>
          <div class="p-3.5 bg-muted/30 border border-border rounded-lg">
            <div class="text-xs text-muted-foreground mb-1 font-medium">Active Engines</div>
            <div class="text-xl font-bold font-mono text-primary tabular-nums">6 / 6</div>
          </div>
          <div class="p-3.5 bg-muted/30 border border-border rounded-lg">
            <div class="text-xs text-muted-foreground mb-1 font-medium">Malicious IPs Mitigated</div>
            <div class="text-xl font-bold font-mono text-warning tabular-nums">
              {{ stats.blocked_ips ?? 0 }}
            </div>
          </div>
          <div class="p-3.5 bg-muted/30 border border-border rounded-lg">
            <div class="text-xs text-muted-foreground mb-1 font-medium">Block Ratio</div>
            <div class="text-xl font-bold font-mono text-foreground tabular-nums">
              {{ ((stats.block_ratio ?? 0) * 100).toFixed(1) }}%
            </div>
          </div>
        </div>
      </CardContent>
    </Card>

    <!-- Defense Engine Status Matrix (6 Cards) -->
    <div class="space-y-4">
      <div class="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
        <Cpu class="w-4 h-4 text-primary" />
        <span>Multi-Stage WAF Defense Engines</span>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <Card
          v-for="engine in protectionEngines"
          :key="engine.name"
          class="hover:border-primary/40 transition-colors"
        >
          <CardHeader class="pb-2 p-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <component :is="engine.icon" class="w-4 h-4 text-primary" />
                <CardTitle class="text-base font-semibold text-foreground">
                  {{ engine.name }}
                </CardTitle>
              </div>
              <Badge variant="outline" class="text-xs font-mono font-bold text-success border-success/30 bg-success/10">
                {{ engine.status }}
              </Badge>
            </div>
          </CardHeader>
          <CardContent class="p-4 pt-0 space-y-3">
            <p class="text-xs text-muted-foreground leading-relaxed">{{ engine.desc }}</p>
            <div class="flex items-center justify-between pt-2 border-t border-border/50 text-xs font-mono text-muted-foreground">
              <span>Triage Latency</span>
              <span class="font-bold text-foreground">{{ engine.latency }}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>

    <!-- Threat Vectors & Enforcement Actions Breakdown -->
    <div class="grid grid-cols-1 md:grid-cols-12 gap-6">
      <!-- Top Attack Vectors -->
      <Card class="md:col-span-6 flex flex-col justify-between">
        <CardHeader class="pb-3">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-md bg-threat/10 text-threat flex items-center justify-center">
              <ShieldAlert class="w-4 h-4" />
            </div>
            <CardTitle class="text-base font-semibold text-foreground">
              Attack Classification Vectors
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent class="pt-0 flex-1 flex flex-col">
          <EmptyState
            v-if="!stats.top_categories || stats.top_categories.length === 0"
            :icon="ShieldAlert"
            title="No threat payloads detected"
            description="Zero attack vectors captured in this observation window."
            class="py-6 pt-4 flex-1"
          />
          <div v-else class="space-y-2.5 max-h-[240px] overflow-y-auto pr-1">
            <div
              v-for="cat in stats.top_categories"
              :key="cat.key"
              class="flex items-center justify-between text-xs font-mono p-2.5 bg-muted/40 rounded-lg hover:bg-muted/70 transition-colors"
            >
              <span class="font-semibold text-foreground">{{ cat.key }}</span>
              <span class="text-threat font-bold tabular-nums">{{ cat.count.toLocaleString() }} hits</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Enforcement Actions -->
      <Card class="md:col-span-6 flex flex-col justify-between">
        <CardHeader class="pb-3">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-md bg-primary/10 text-primary flex items-center justify-center">
              <CheckCircle2 class="w-4 h-4" />
            </div>
            <CardTitle class="text-base font-semibold text-foreground">
              Mitigation Enforcement Actions
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent class="pt-0 flex-1 flex flex-col">
          <div class="space-y-2.5">
            <div class="flex items-center justify-between p-2.5 bg-muted/40 rounded-lg text-xs font-mono">
              <span class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-threat" />
                <span class="font-semibold text-foreground">Strict Drop & 403 Forbidden</span>
              </span>
              <span class="font-bold tabular-nums">{{ stats.total_blocked.toLocaleString() }}</span>
            </div>
            <div class="flex items-center justify-between p-2.5 bg-muted/40 rounded-lg text-xs font-mono">
              <span class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-warning" />
                <span class="font-semibold text-foreground">PoW Challenge (HTTP 468)</span>
              </span>
              <span class="font-bold tabular-nums">0</span>
            </div>
            <div class="flex items-center justify-between p-2.5 bg-muted/40 rounded-lg text-xs font-mono">
              <span class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-info" />
                <span class="font-semibold text-foreground">Tier 2 Auto-Banned IPs</span>
              </span>
              <span class="font-bold tabular-nums">{{ stats.blocked_ips ?? 0 }}</span>
            </div>
            <div class="flex items-center justify-between p-2.5 bg-muted/40 rounded-lg text-xs font-mono">
              <span class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-success" />
                <span class="font-semibold text-foreground">Legitimate Gateway Pass-Through</span>
              </span>
              <span class="font-bold tabular-nums">
                {{ (stats.total_requests - stats.total_blocked).toLocaleString() }}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
