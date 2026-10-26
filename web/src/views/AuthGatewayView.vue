<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from '@/router';
import AuthLogsTable from '@/components/identity/AuthLogsTable.vue';
import UserDirectoryTable from '@/components/UserDirectoryTable.vue';
import SsoPortalPanel from '@/components/identity/SsoPortalPanel.vue';
import IdPListPanel from '@/components/identity/IdPListPanel.vue';
import { Tabs, type Tab } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { KeyRound, Lock, MonitorDot, ScrollText, Users } from 'lucide-vue-next';

type AuthTab = 'logs' | 'users' | 'sso' | 'idp';

const route = useRoute();
const router = useRouter();

const activeTab = computed<AuthTab>(() => {
  const path = route.value.path || '';
  if (path.includes('users')) return 'users';
  if (path.includes('sso')) return 'sso';
  if (path.includes('idp')) return 'idp';
  return 'logs';
});

const tabs: (Tab & { id: AuthTab })[] = [
  {
    id: 'logs',
    label: 'Authentication Logs',
    icon: ScrollText,
    description: 'Login attempts across every protected site — newest first',
    testId: 'tab-auth-logs',
  },
  {
    id: 'users',
    label: 'User Management',
    icon: Users,
    description: 'Directory accounts, app bindings, passwords, and 2FA',
    testId: 'tab-auth-users',
  },
  {
    id: 'sso',
    label: 'Single Sign-On',
    icon: MonitorDot,
    description: 'Per-site portal enforcement and shared clearance binding',
    testId: 'tab-auth-sso',
  },
  {
    id: 'idp',
    label: 'Login Configuration',
    icon: KeyRound,
    description: 'External directory connectors: OIDC, LDAP, GitHub OAuth2',
    testId: 'tab-auth-idp',
  },
];

const handleTabChange = (tabId: string) => {
  const map: Record<AuthTab, string> = {
    logs: '/auth-gateway/logs',
    users: '/auth-gateway/users',
    sso: '/auth-gateway/sso',
    idp: '/auth-gateway/idp',
  };
  router.push(map[tabId as AuthTab] ?? '/auth-gateway/logs');
};
</script>

<template>
  <div class="h-full flex flex-col space-y-6 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <div class="flex flex-wrap items-start justify-between gap-3 shrink-0">
      <div class="min-w-0">
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <Lock class="w-5 h-5 text-muted-foreground" />
          <span>Auth Gateway</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Unified directory identity for protected sites — HTTP 467 portal, app bindings, 2FA, and external IdPs.
        </p>
      </div>
      <Badge variant="outline" class="font-mono text-xs uppercase">
        Pre-App Auth · OIDC · MFA · RBAC
      </Badge>
    </div>

    <div class="border-b border-border pb-1.5 shrink-0">
      <Tabs :tabs="tabs" :active-tab="activeTab" @tab-change="handleTabChange" />
    </div>

    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <AuthLogsTable v-if="activeTab === 'logs'" data-testid="auth-panel-logs" />
      <UserDirectoryTable v-else-if="activeTab === 'users'" data-testid="auth-panel-users" />
      <SsoPortalPanel v-else-if="activeTab === 'sso'" data-testid="auth-panel-sso" />
      <IdPListPanel v-else data-testid="auth-panel-idp" />
    </div>
  </div>
</template>
