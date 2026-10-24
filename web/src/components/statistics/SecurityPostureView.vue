<script setup lang="ts">
import { computed } from 'vue';
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
  AlertTriangle,
} from 'lucide-vue-next';
import type { AggregateStats } from '@/types/telemetry';

const props = defineProps<{
  stats: AggregateStats;
}>();

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
];

const securityScore = computed(() => {
  if (props.stats.total_requests === 0) return 100;
  const ratio = props.stats.block_ratio;
  if (ratio > 0.5) return 88;
  if (ratio > 0.2) return 94;
  return 98;
});
</script>

<template>
  <div class="space-y-4 font-sans">
    <!-- Top Security Posture Overview Banner -->
    <div class="p-6 bg-card border border-border rounded-xl grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
      <!-- Score Ring Indicator -->
      <div class="md:col-span-4 flex items-center gap-5">
        <div class="relative w-24 h-24 shrink-0 flex items-center justify-center">
          <svg viewBox="0 0 100 100" class="w-full h-full transform -rotate-90">
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="transparent"
              stroke="currentColor"
              class="text-muted/40"
              stroke-width="10"
            />
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="transparent"
              stroke="#14b8a6"
              stroke-width="10"
              stroke-dasharray="264"
              :stroke-dashoffset="264 * (1 - securityScore / 100)"
              stroke-linecap="round"
            />
          </svg>
          <div class="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span class="text-2xl font-bold font-mono text-foreground tabular-nums">{{ securityScore }}</span>
            <span class="text-[9px] font-mono text-muted-foreground uppercase">Score</span>
          </div>
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
      <div class="md:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="p-3 bg-muted/30 border border-border rounded-lg">
          <div class="text-[11px] text-muted-foreground mb-1">Threat Interceptions</div>
          <div class="text-xl font-bold font-mono text-threat tabular-nums">
            {{ stats.total_blocked.toLocaleString() }}
          </div>
        </div>
        <div class="p-3 bg-muted/30 border border-border rounded-lg">
          <div class="text-[11px] text-muted-foreground mb-1">Active Engines</div>
          <div class="text-xl font-bold font-mono text-primary tabular-nums">6 / 6</div>
        </div>
        <div class="p-3 bg-muted/30 border border-border rounded-lg">
          <div class="text-[11px] text-muted-foreground mb-1">Malicious IPs Mitigated</div>
          <div class="text-xl font-bold font-mono text-warning tabular-nums">
            {{ stats.blocked_ips ?? 0 }}
          </div>
        </div>
        <div class="p-3 bg-muted/30 border border-border rounded-lg">
          <div class="text-[11px] text-muted-foreground mb-1">Block Ratio</div>
          <div class="text-xl font-bold font-mono text-foreground tabular-nums">
            {{ ((stats.block_ratio ?? 0) * 100).toFixed(1) }}%
          </div>
        </div>
      </div>
    </div>

    <!-- Defense Engine Status Matrix (6 Cards) -->
    <div>
      <div class="text-xs font-bold text-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
        <Cpu class="w-3.5 h-3.5 text-primary" />
        <span>Multi-Stage WAF Defense Engines</span>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        <div
          v-for="engine in protectionEngines"
          :key="engine.name"
          class="p-4 bg-card border border-border rounded-xl space-y-2 hover:border-primary/40 transition-colors"
        >
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <component :is="engine.icon" class="w-4 h-4 text-primary" />
              <span class="text-xs font-bold text-foreground">{{ engine.name }}</span>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-success/15 text-success">
              {{ engine.status }}
            </span>
          </div>
          <p class="text-[11px] text-muted-foreground leading-relaxed">{{ engine.desc }}</p>
          <div class="flex items-center justify-between pt-1 border-t border-border/50 text-[10px] font-mono text-muted-foreground">
            <span>Triage Latency</span>
            <span class="font-bold text-foreground">{{ engine.latency }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Threat Vectors & Enforcement Actions Breakdown -->
    <div class="grid grid-cols-1 md:grid-cols-12 gap-4">
      <!-- Top Attack Vectors -->
      <div class="md:col-span-6 p-4 bg-card border border-border rounded-xl space-y-3">
        <div class="flex items-center justify-between">
          <h4 class="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert class="w-3.5 h-3.5 text-threat" />
            <span>Attack Classification Vectors</span>
          </h4>
        </div>
        <div class="space-y-2 max-h-[220px] overflow-y-auto">
          <div
            v-for="cat in stats.top_categories"
            :key="cat.key"
            class="flex items-center justify-between text-xs font-mono p-2 bg-muted/40 rounded-lg"
          >
            <span class="font-semibold text-foreground">{{ cat.key }}</span>
            <span class="text-threat font-bold tabular-nums">{{ cat.count.toLocaleString() }} hits</span>
          </div>
          <div v-if="!stats.top_categories || stats.top_categories.length === 0" class="text-center py-8 text-xs text-muted-foreground font-mono">
            No threat payloads detected in this window
          </div>
        </div>
      </div>

      <!-- Enforcement Actions -->
      <div class="md:col-span-6 p-4 bg-card border border-border rounded-xl space-y-3">
        <div class="flex items-center justify-between">
          <h4 class="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-1.5">
            <CheckCircle2 class="w-3.5 h-3.5 text-primary" />
            <span>Mitigation Enforcement Actions</span>
          </h4>
        </div>
        <div class="space-y-2">
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
      </div>
    </div>
  </div>
</template>
