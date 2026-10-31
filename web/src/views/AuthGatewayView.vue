<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from '@/router';
import AuthLogsTable from '@/components/identity/AuthLogsTable.vue';
import UserDirectoryTable from '@/components/UserDirectoryTable.vue';
import SsoPortalPanel from '@/components/identity/SsoPortalPanel.vue';
import IdPListPanel from '@/components/identity/IdPListPanel.vue';
import { Lock, Users, KeyRound, ScrollText } from 'lucide-vue-next';

type AuthTab = 'logs' | 'users' | 'sso' | 'idp';

const route = useRoute();

const activeTab = computed<AuthTab>(() => {
  const path = route.value.path || '';
  if (path.includes('users')) return 'users';
  if (path.includes('sso')) return 'sso';
  if (path.includes('idp')) return 'idp';
  return 'logs';
});

const headerInfo = computed(() => {
  switch (activeTab.value) {
    case 'users':
      return {
        title: 'User Management',
        description: 'Directory user accounts, operator credentials, roles, and two-factor authentication devices.',
        icon: Users,
      };
    case 'sso':
      return {
        title: 'Single Sign-On',
        description: 'HTTP 467 pre-application portal bindings, session durations, and per-site clearance rules.',
        icon: KeyRound,
      };
    case 'idp':
      return {
        title: 'Login Configuration',
        description: 'External identity providers (IdP) via OpenID Connect (OIDC), LDAP, and OAuth2 federation.',
        icon: Lock,
      };
    case 'logs':
    default:
      if (route.value.path === '/auth-gateway') {
        return {
          title: 'Auth Gateway',
          description: 'Unified directory identity for protected sites — HTTP 467 portal, app bindings, 2FA, and external IdPs.',
          icon: Lock,
        };
      }
      return {
        title: 'Authentication Logs',
        description: 'Real-time and historical directory authentication attempts, MFA challenges, and clearance records.',
        icon: ScrollText,
      };
  }
});
</script>

<template>
  <div class="space-y-6 font-sans">
    <div class="border-b border-border pb-4">
      <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
        <component :is="headerInfo.icon" class="w-5 h-5 text-muted-foreground" />
        <span>{{ headerInfo.title }}</span>
      </h1>
      <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
        {{ headerInfo.description }}
      </p>
    </div>

    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <AuthLogsTable v-if="activeTab === 'logs'" key="panel-logs" data-testid="auth-panel-logs" />
      <UserDirectoryTable v-else-if="activeTab === 'users'" key="panel-users" data-testid="auth-panel-users" />
      <SsoPortalPanel v-else-if="activeTab === 'sso'" key="panel-sso" data-testid="auth-panel-sso" />
      <IdPListPanel v-else key="panel-idp" data-testid="auth-panel-idp" />
    </div>
  </div>
</template>
