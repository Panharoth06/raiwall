<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRouter } from '@/router';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import {
  ArrowLeft,
  Plus,
  Edit2,
  CheckCircle2,
  Sliders,
} from 'lucide-vue-next';
import RateLimitRuleModal, {
  type LimitTierType,
  type RuleFormData,
} from './RateLimitRuleModal.vue';

const router = useRouter();
const configStore = useConfigStore();

const form = ref<PolicySettings>({
  tier1_rate: 100,
  tier1_burst: 200,
  tier2_threshold: 10,
  tier2_ban_seconds: 1800,
  tier3_threshold: 10,
  tier3_ban_seconds: 1800,
  bot_defense_mode: 'defense',
  pow_difficulty: 20000,
  honeypot_enabled: true,
  waiting_room_enabled: false,
  waiting_room_max_concurrent: 1000,
  waiting_room_paths: [],
});

const accessEnabled = ref(true);
const attackEnabled = ref(true);
const errorEnabled = ref(true);
const savedToast = ref(false);
const toastMessage = ref('');

// Modal state
const modalOpen = ref(false);
const activeTier = ref<LimitTierType>('access');
const initialModalData = ref<Partial<RuleFormData>>({});

onMounted(() => {
  if (configStore.policies) {
    syncFromPolicies(configStore.policies);
  }
});

watch(
  () => configStore.policies,
  (val) => {
    if (val) {
      syncFromPolicies(val);
    }
  }
);

function syncFromPolicies(p: PolicySettings) {
  form.value = { ...p };
  accessEnabled.value = (p.tier1_rate ?? 100) > 0;
  attackEnabled.value = (p.tier2_threshold ?? 10) > 0;
  errorEnabled.value = (p.tier3_threshold ?? 10) > 0;
}

const showToast = (msg: string) => {
  toastMessage.value = msg;
  savedToast.value = true;
  setTimeout(() => {
    savedToast.value = false;
  }, 2500);
};

const handleToggle = async (tier: LimitTierType, val: boolean) => {
  if (tier === 'access') {
    accessEnabled.value = val;
    if (!val) {
      form.value.tier1_rate = 0;
    } else if (form.value.tier1_rate === 0) {
      form.value.tier1_rate = 100;
    }
  } else if (tier === 'attack') {
    attackEnabled.value = val;
    if (!val) {
      form.value.tier2_threshold = 0;
    } else if (form.value.tier2_threshold === 0) {
      form.value.tier2_threshold = 10;
    }
  } else if (tier === 'error') {
    errorEnabled.value = val;
    if (!val) {
      form.value.tier3_threshold = 0;
    } else if (form.value.tier3_threshold === 0) {
      form.value.tier3_threshold = 10;
    }
  }

  await configStore.savePolicies(form.value);
  showToast(`${tier.charAt(0).toUpperCase() + tier.slice(1)} limit ${val ? 'enabled' : 'disabled'}`);
};

const openEditModal = (tier: LimitTierType) => {
  activeTier.value = tier;
  if (tier === 'access') {
    initialModalData.value = {
      name: 'Basic Access Limit',
      threshold: form.value.tier1_rate || 100,
      window_seconds: 10,
      action: 'challenge',
      duration_minutes: 60,
    };
  } else if (tier === 'attack') {
    initialModalData.value = {
      name: 'Basic Attack Limit',
      threshold: form.value.tier2_threshold || 10,
      window_seconds: 60,
      action: 'block',
      duration_minutes: Math.round((form.value.tier2_ban_seconds || 1800) / 60),
    };
  } else {
    initialModalData.value = {
      name: 'Basic Error Limit',
      threshold: form.value.tier3_threshold || 10,
      window_seconds: 10,
      action: 'block',
      duration_minutes: Math.round((form.value.tier3_ban_seconds || 1800) / 60),
    };
  }
  modalOpen.value = true;
};

const handleSaveRule = async ({ tier, values }: { tier: LimitTierType; values: RuleFormData }) => {
  if (tier === 'access') {
    form.value.tier1_rate = values.threshold;
    form.value.tier1_burst = values.threshold * 2;
    accessEnabled.value = true;
  } else if (tier === 'attack') {
    form.value.tier2_threshold = values.threshold;
    form.value.tier2_ban_seconds = values.duration_minutes * 60;
    attackEnabled.value = true;
  } else if (tier === 'error') {
    form.value.tier3_threshold = values.threshold;
    form.value.tier3_ban_seconds = values.duration_minutes * 60;
    errorEnabled.value = true;
  }

  await configStore.savePolicies(form.value);
  showToast(`Updated ${tier} limiting policy`);
};

const goBackToLimits = () => {
  router.push('/http-flood/limits');
};
</script>

<template>
  <div class="space-y-4">
    <!-- Top Action Bar -->
    <div class="flex items-center justify-end">
      <Button
        variant="outline"
        size="sm"
        class="h-8 gap-1.5 text-xs font-medium"
        @click="goBackToLimits"
      >
        <ArrowLeft class="w-3.5 h-3.5" />
        <span>Back to Rate Limiting</span>
      </Button>
    </div>

    <!-- Feedback Banner -->
    <div
      v-if="savedToast"
      class="p-2.5 bg-primary/10 border border-primary/30 rounded-md flex items-center gap-2 text-primary text-xs"
    >
      <CheckCircle2 class="w-4 h-4 text-primary shrink-0" />
      <span>{{ toastMessage || 'Settings staged to configuration draft successfully.' }}</span>
    </div>

    <!-- Limiting Panels Strip -->
    <div class="space-y-4">
      <!-- 1. Access Limiting -->
      <Card class="bg-card border-border shadow-none">
        <CardHeader class="py-3 px-4 border-b border-border/60 flex flex-row items-center justify-between">
          <div class="flex items-center gap-2">
            <Sliders class="w-4 h-4 text-primary" />
            <CardTitle class="text-xs font-semibold uppercase tracking-wider text-foreground">
              Access Limiting (Tier 1: Access Velocity Limiting)
            </CardTitle>
          </div>
          <Button
            variant="outline"
            size="sm"
            class="h-7 px-2.5 text-xs gap-1 font-medium"
            @click="openEditModal('access')"
          >
            <Plus class="w-3 h-3" />
            <span>ADD RULES</span>
          </Button>
        </CardHeader>
        <CardContent class="p-4">
          <div class="flex items-center justify-between gap-4">
            <div class="flex items-start gap-3 flex-1 min-w-0">
              <Switch
                :checked="accessEnabled"
                @update:checked="(val) => handleToggle('access', val)"
                class="mt-0.5"
              />
              <div class="space-y-0.5 min-w-0">
                <div class="text-xs font-semibold text-foreground">
                  Basic Access Limit
                </div>
                <p class="text-xs text-muted-foreground leading-relaxed">
                  An IP that makes
                  <span class="font-mono font-medium text-foreground">{{ form.tier1_rate || 100 }} requests</span>
                  within
                  <span class="font-mono font-medium text-foreground">10 seconds</span>
                  will require Anti-Bot challenge when accessing again within the next
                  <span class="font-mono font-medium text-foreground">60 minutes</span>.
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 text-xs font-medium text-primary hover:text-primary hover:bg-primary/10"
              @click="openEditModal('access')"
            >
              EDIT
            </Button>
          </div>
        </CardContent>
      </Card>

      <!-- 2. Attack Limiting -->
      <Card class="bg-card border-border shadow-none">
        <CardHeader class="py-3 px-4 border-b border-border/60 flex flex-row items-center justify-between">
          <div class="flex items-center gap-2">
            <Sliders class="w-4 h-4 text-primary" />
            <CardTitle class="text-xs font-semibold uppercase tracking-wider text-foreground">
              Attack Limiting (Tier 2: Attack Frequency Auto-Ban)
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent class="p-4">
          <div class="flex items-center justify-between gap-4">
            <div class="flex items-start gap-3 flex-1 min-w-0">
              <Switch
                :checked="attackEnabled"
                @update:checked="(val) => handleToggle('attack', val)"
                class="mt-0.5"
              />
              <div class="space-y-0.5 min-w-0">
                <div class="text-xs font-semibold text-foreground">
                  Basic Attack Limit
                </div>
                <p class="text-xs text-muted-foreground leading-relaxed">
                  An IP that triggers attack blocking
                  <span class="font-mono font-medium text-foreground">{{ form.tier2_threshold || 10 }} times</span>
                  within
                  <span class="font-mono font-medium text-foreground">60 seconds</span>
                  will be automatically blocked
                  <span class="font-mono font-medium text-foreground">{{ Math.round((form.tier2_ban_seconds || 1800) / 60) }} minutes</span>.
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 text-xs font-medium text-primary hover:text-primary hover:bg-primary/10"
              @click="openEditModal('attack')"
            >
              EDIT
            </Button>
          </div>
        </CardContent>
      </Card>

      <!-- 3. Error Limiting -->
      <Card class="bg-card border-border shadow-none">
        <CardHeader class="py-3 px-4 border-b border-border/60 flex flex-row items-center justify-between">
          <div class="flex items-center gap-2">
            <Sliders class="w-4 h-4 text-primary" />
            <CardTitle class="text-xs font-semibold uppercase tracking-wider text-foreground">
              Error Limiting (Tier 3: Upstream Scanner Trap)
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent class="p-4">
          <div class="flex items-center justify-between gap-4">
            <div class="flex items-start gap-3 flex-1 min-w-0">
              <Switch
                :checked="errorEnabled"
                @update:checked="(val) => handleToggle('error', val)"
                class="mt-0.5"
              />
              <div class="space-y-0.5 min-w-0">
                <div class="text-xs font-semibold text-foreground">
                  Basic Error Limit
                </div>
                <p class="text-xs text-muted-foreground leading-relaxed">
                  An IP that triggers 403, 404 errors
                  <span class="font-mono font-medium text-foreground">{{ form.tier3_threshold || 10 }} times</span>
                  within
                  <span class="font-mono font-medium text-foreground">10 seconds</span>
                  will be automatically blocked for
                  <span class="font-mono font-medium text-foreground">{{ Math.round((form.tier3_ban_seconds || 1800) / 60) }} minutes</span>.
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 text-xs font-medium text-primary hover:text-primary hover:bg-primary/10"
              @click="openEditModal('error')"
            >
              EDIT
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>

    <!-- Rule Config Modal -->
    <RateLimitRuleModal
      v-model:open="modalOpen"
      :tier="activeTier"
      :initial-data="initialModalData"
      @save="handleSaveRule"
    />
  </div>
</template>
