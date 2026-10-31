<script setup lang="ts">
import { Button } from '@/components/ui/button';
import DetectionHeroBanner from '@/components/detection/DetectionHeroBanner.vue';
import { useHeroBanner } from '@/components/detection/useHeroBanner';
import DetectionPageHeader from '@/components/detection/DetectionPageHeader.vue';
import RuleTesterPanel from '@/components/rules/RuleTesterPanel.vue';
import { FlaskConical, HelpCircle } from 'lucide-vue-next';

const { showHero, toggleHero, dismissHero } = useHeroBanner('detection-tester');
</script>

<template>
  <div class="space-y-4 font-sans">
    <DetectionPageHeader
      title="Rule Tester"
      description="Evaluate a synthetic request against the active detection engine."
      :icon="FlaskConical"
    >
      <template #actions>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :data-testid="'hero-toggle-tester'"
          @click="toggleHero"
        >
          <HelpCircle class="w-3.5 h-3.5 text-primary" />
          <span>{{ showHero ? 'Hide Guide' : 'Explain feature' }}</span>
        </Button>
      </template>
    </DetectionPageHeader>

    <!-- Prominent Hero Section with Low-Opacity Background Icon -->
    <DetectionHeroBanner
      storage-key="detection-tester"
      title="WAF Rule Tester & Request Simulator"
      badge="PLAYGROUND"
      description="Test synthetic HTTP requests directly against Raiwall's running detection engine before applying rules to live production traffic. Simulate specific HTTP methods, headers, query parameters, and request bodies to see real-time match verdicts, anomaly scores, triggered rules, and whether the request would be blocked, challenged, or allowed."
      :icon="FlaskConical"
      :highlights="[
        { label: 'Real-Time Verdicts', text: 'Tests across CRS, pure-Go AST parsers, and custom rule packs simultaneously.' },
        { label: 'Zero Production Impact', text: 'Executes safely in-memory without affecting active sessions or metrics.' },
        { label: 'Full Diagnostic Trace', text: 'Inspects matched rule IDs, severity scores, and exact offending parameter substrings.' },
      ]"
      v-model:open="showHero"
      @dismiss="dismissHero"
    />

    <RuleTesterPanel />
  </div>
</template>
