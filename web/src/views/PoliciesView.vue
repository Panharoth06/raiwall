<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import { Button } from '@/components/ui/button';
import { NumberInput } from '@/components/ui/number-input';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '@/components/ui/card';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Sliders, Flame, Bot, Save, CheckCircle2 } from 'lucide-vue-next';

const configStore = useConfigStore();

const form = ref<PolicySettings>({
  tier1_rate: 100,
  tier1_burst: 200,
  tier2_threshold: 10,
  tier2_ban_seconds: 3600,
  tier3_threshold: 25,
  tier3_ban_seconds: 7200,
  bot_defense_mode: 'defense',
  pow_difficulty: 20000,
  honeypot_enabled: true,
  waiting_room_enabled: false,
  waiting_room_max_concurrent: 1000,
});

const savedNotification = ref(false);

onMounted(() => {
  if (configStore.policies) {
    form.value = { ...configStore.policies };
  }
});

watch(
  () => configStore.policies,
  (val) => {
    if (val) {
      form.value = { ...val };
    }
  }
);

const handleSave = async () => {
  await configStore.savePolicies(form.value);
  savedNotification.value = true;
  setTimeout(() => {
    savedNotification.value = false;
  }, 3000);
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Sliders class="w-4 h-4 text-muted-foreground" />
          <span>Security & DDoS Defense Policies</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Multi-tier rate limits, stateless SHA-256 bot challenges, and scanner trap thresholds.
        </p>
      </div>

      <Button
        @click="handleSave"
        class="gap-1.5"
      >
        <Save class="w-3.5 h-3.5" />
        <span>Save Policies to Draft</span>
      </Button>
    </div>

    <div v-if="savedNotification" class="p-2.5 bg-success/10 border border-success/30 rounded-md flex items-center gap-2 text-success text-xs">
      <CheckCircle2 class="w-4 h-4 text-success" />
      <span>Security policies saved to draft configuration. Review and deploy in Deployments view.</span>
    </div>

    <!-- Scrollable Content -->
    <div class="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1">
      <!-- 3-Tier Rate Limiting -->
      <Card>
        <CardHeader class="pb-2">
          <div class="flex items-center gap-2">
            <Flame class="w-4 h-4 text-muted-foreground" />
            <CardTitle class="text-xs uppercase tracking-wider text-foreground">
              Three-Tiered Composite Rate Limiting
            </CardTitle>
          </div>
          <CardDescription class="text-sm text-muted-foreground mt-1 leading-relaxed">
            Layered threshold defense protecting against high-velocity floods, repeated exploit attacks, and vulnerability scanners.
          </CardDescription>
        </CardHeader>

        <CardContent class="space-y-3 pt-2">
          <div class="grid grid-cols-2 gap-4">
            <!-- Tier 1 -->
            <div class="p-3 bg-muted/50 border border-border rounded-md space-y-2.5">
              <span class="text-xs font-semibold text-foreground block font-sans">Tier 1: Velocity Rate Limit (PoW Trigger)</span>
              <div>
                <label class="block text-[10px] uppercase font-mono text-muted-foreground mb-1">Max Requests / Sec</label>
                <NumberInput
                  v-model="form.tier1_rate"
                  :min="1"
                  suffix="/s"
                  class="shadow-none"
                />
              </div>
              <div>
                <label class="block text-[10px] uppercase font-mono text-muted-foreground mb-1">Burst Capacity</label>
                <NumberInput
                  v-model="form.tier1_burst"
                  :min="1"
                  suffix="reqs"
                  class="shadow-none"
                />
              </div>
            </div>

            <!-- Tier 2 -->
            <div class="p-3 bg-muted/50 border border-border rounded-md space-y-2.5">
              <span class="text-xs font-semibold text-foreground block font-sans">Tier 2: Attack Frequency Auto-Ban</span>
              <div>
                <label class="block text-[10px] uppercase font-mono text-muted-foreground mb-1">Threat Threshold (Violations in 10s)</label>
                <NumberInput
                  v-model="form.tier2_threshold"
                  :min="1"
                  suffix="pts"
                  class="shadow-none"
                />
              </div>
              <div>
                <label class="block text-[10px] uppercase font-mono text-muted-foreground mb-1">Ban Duration (Seconds)</label>
                <NumberInput
                  v-model="form.tier2_ban_seconds"
                  :min="1"
                  suffix="sec"
                  class="shadow-none"
                />
              </div>
            </div>
          </div>

          <!-- Tier 3 -->
          <div class="p-3 bg-muted/50 border border-border rounded-md space-y-2.5">
            <span class="text-xs font-semibold text-foreground block font-sans">Tier 3: Upstream Scanner Trap (403/404 Abuse)</span>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-[10px] uppercase font-mono text-muted-foreground mb-1">Scanner 403/404 Threshold</label>
                <NumberInput
                  v-model="form.tier3_threshold"
                  :min="1"
                  suffix="reqs"
                  class="shadow-none"
                />
              </div>
              <div>
                <label class="block text-[10px] uppercase font-mono text-muted-foreground mb-1">Scanner Ban Duration (Seconds)</label>
                <NumberInput
                  v-model="form.tier3_ban_seconds"
                  :min="1"
                  suffix="sec"
                  class="shadow-none"
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Active Bot Defense -->
      <Card>
        <CardHeader class="pb-2">
          <div class="flex items-center gap-2">
            <Bot class="w-4 h-4 text-muted-foreground" />
            <CardTitle class="text-xs uppercase tracking-wider text-foreground">
              Active Bot Defense & Proof-of-Work
            </CardTitle>
          </div>
        </CardHeader>

        <CardContent class="space-y-4 pt-2">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-[10px] font-semibold text-muted-foreground uppercase font-mono tracking-wider mb-1">Challenge Mode</label>
              <Select v-model="form.bot_defense_mode">
                <SelectTrigger class="w-full h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="defense">Defense (Issue HTTP 468 PoW Challenge)</SelectItem>
                  <SelectItem value="challenge">Interactive Challenge Always</SelectItem>
                  <SelectItem value="audit">Audit Only (Fingerprint without challenge)</SelectItem>
                  <SelectItem value="off">Disabled</SelectItem>
                </SelectContent>
              </Select>
              <select v-model="form.bot_defense_mode" class="sr-only" tabindex="-1" aria-hidden="true">
                <option value="defense">Defense</option>
                <option value="challenge">Interactive Challenge Always</option>
                <option value="audit">Audit Only</option>
                <option value="off">Disabled</option>
              </select>
            </div>

            <div>
              <label class="block text-[10px] font-semibold text-muted-foreground uppercase font-mono tracking-wider mb-1">
                PoW SHA-256 Difficulty: {{ form.pow_difficulty }}
              </label>
              <input
                v-model.number="form.pow_difficulty"
                type="range"
                min="5000"
                max="100000"
                step="5000"
                class="w-full accent-primary cursor-pointer"
              />
            </div>
          </div>

          <div class="pt-1 flex items-center gap-2.5">
            <input
              id="honeypot"
              v-model="form.honeypot_enabled"
              type="checkbox"
              class="h-4 w-4 rounded bg-card border-input text-primary focus:ring-ring cursor-pointer"
            />
            <label for="honeypot" class="text-xs text-foreground cursor-pointer font-sans">
              Inject invisible honeypot trap hyperlinks into HTML responses to trap headless crawlers
            </label>
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
