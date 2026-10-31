<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from '@/router';
import {
  detectionApi,
  type AppDetectionPolicy,
  type DetectionStatus,
  type WAFPolicy,
} from '@/api/detection';
import { Button } from '@/components/ui/button';
import DetectionHeroBanner from '@/components/detection/DetectionHeroBanner.vue';
import { useHeroBanner } from '@/components/detection/useHeroBanner';
import DetectionPageHeader from '@/components/detection/DetectionPageHeader.vue';
import DetectionStatusStrip from '@/components/detection/DetectionStatusStrip.vue';
import PolicyPresetEditor from '@/components/detection/PolicyPresetEditor.vue';
import DetectionAppPolicyTable from '@/components/detection/DetectionAppPolicyTable.vue';
import { HelpCircle, RefreshCw, ShieldCheck } from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();

const { showHero, toggleHero, dismissHero } = useHeroBanner('detection-overview');
const status = ref<DetectionStatus | null>(null);
const policy = ref<WAFPolicy>({
  detection_mode: 'inherit',
  sensitivity: 'inherit',
});
const appPolicies = ref<AppDetectionPolicy[]>([]);
const loading = ref(true);
const saving = ref(false);
const error = ref('');
const saved = ref('');

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    const [statusResult, policyResult, appsResult] = await Promise.all([
      detectionApi.getStatus(),
      detectionApi.getPolicy(),
      detectionApi.listAppPolicies(),
    ]);
    status.value = statusResult;
    // Edit the resolved policy so process-level CRS defaults are visible.
    policy.value = policyResult.resolved;
    appPolicies.value = appsResult.policies;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load detection configuration';
  } finally {
    loading.value = false;
  }
};

const savePolicy = async (next: WAFPolicy) => {
  saving.value = true;
  error.value = '';
  saved.value = '';
  try {
    await detectionApi.setPolicy(next);
    await load();
    saved.value = 'Detection policy applied to the active snapshot.';
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to apply detection policy';
  } finally {
    saving.value = false;
  }
};

const updateAppPolicy = async (appID: string, next: WAFPolicy) => {
  saving.value = true;
  error.value = '';
  saved.value = '';
  try {
    await detectionApi.setAppPolicy(appID, next);
    await load();
    saved.value = `Detection policy updated for ${appID}.`;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to update site policy';
  } finally {
    saving.value = false;
  }
};

const resetAppPolicy = async (appID: string) => {
  saving.value = true;
  error.value = '';
  saved.value = '';
  try {
    await detectionApi.resetAppPolicy(appID);
    await load();
    saved.value = `${appID} now inherits the global detection policy.`;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to reset site policy';
  } finally {
    saving.value = false;
  }
};

onMounted(() => {
  const tab = route.value.query.tab;
  const redirects: Record<string, string> = {
    tester: '/detection/tester',
    exceptions: '/detection/exceptions',
    acls: '/allow-deny',
    policies: '/http-flood/limits',
  };
  if (tab && redirects[tab]) {
    router.replace(redirects[tab]);
    return;
  }
  load();
});
</script>

<template>
  <div class="space-y-4 font-sans">
    <DetectionPageHeader
      title="Detection & Security Policy"
      description="Effective detection posture across semantic modules, virtual patches, and OWASP CRS."
      :icon="ShieldCheck"
    >
      <template #actions>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :data-testid="'hero-toggle-overview'"
          @click="toggleHero"
        >
          <HelpCircle class="w-3.5 h-3.5 text-primary" />
          <span>{{ showHero ? 'Hide Guide' : 'Explain feature' }}</span>
        </Button>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :disabled="loading"
          @click="load"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          <span>Refresh</span>
        </Button>
      </template>
    </DetectionPageHeader>

    <!-- Prominent Hero Section with Low-Opacity Background Icon -->
    <DetectionHeroBanner
      storage-key="detection-overview"
      title="WAF Threat Detection & Policy Control Center"
      badge="CORE PROTECTION"
      description="Raiwall automatically analyzes every incoming web request across multiple inspection layers — input normalizers, fast-path lexical scanners (< 2µs), deep AST context parsers (SQL, Shell, XSS), and 87 CVE virtual patches. The default Balanced Defense posture requires zero tuning and protects your web apps against OWASP Top 10 exploits without false alarms."
      :icon="ShieldCheck"
      :highlights="[
        { label: 'Zero-Config Setup', text: 'Balanced Defense is pre-tuned for production web apps, REST APIs, and modern SPAs.' },
        { label: 'Sub-Microsecond Speed', text: 'Fast-path lexical triage screens safe requests in < 2µs without GC pauses.' },
        { label: 'Self-Service Bypasses', text: 'Easily whitelist false positives under Exceptions without turning off the WAF.' },
      ]"
      v-model:open="showHero"
      @dismiss="dismissHero"
    />

    <div
      v-if="error"
      class="flex items-center justify-between gap-3 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-xs text-threat"
      data-testid="detection-error"
    >
      <span class="truncate">{{ error }}</span>
      <Button size="sm" variant="outline" class="h-7 text-xs gap-1 shrink-0" @click="load">
        <RefreshCw class="w-3 h-3" />
        <span>Retry</span>
      </Button>
    </div>

    <p v-if="saved" class="text-xs text-success" data-testid="detection-saved">{{ saved }}</p>

    <DetectionStatusStrip :status="status" :loading="loading" />

    <section class="rounded-xl border border-border bg-card">
      <header class="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 class="text-sm font-semibold text-foreground">Global Detection Policy</h2>
          <p class="text-xs text-muted-foreground">Applies default security posture to all incoming traffic across all applications.</p>
        </div>
      </header>
      <div class="p-4">
        <PolicyPresetEditor :policy="policy" :saving="saving" @save="savePolicy" />
      </div>
    </section>

    <section class="space-y-2">
      <div class="flex items-center justify-between gap-2">
        <h2 class="text-sm font-semibold text-foreground">Per-site policies</h2>
        <span class="text-xs font-mono text-muted-foreground">
          {{ appPolicies.length }} application{{ appPolicies.length === 1 ? '' : 's' }}
        </span>
      </div>
      <DetectionAppPolicyTable
        :policies="appPolicies"
        :saving="saving"
        @update="updateAppPolicy"
        @reset="resetAppPolicy"
      />
    </section>
  </div>
</template>
