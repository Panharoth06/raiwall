<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from '@/router';
import { useConfigStore } from '@/stores/config';
import {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import { LayoutDashboard } from 'lucide-vue-next';

export interface BreadcrumbSegment {
  label: string;
  path?: string;
  isLast?: boolean;
}

const route = useRoute();
const router = useRouter();
const configStore = useConfigStore();

const navigateTo = (path?: string) => {
  if (path) {
    router.push(path);
  }
};

const breadcrumbs = computed<BreadcrumbSegment[]>(() => {
  const path = route.value.path || '/';
  const query = route.value.query || {};
  const params = route.value.params || {};

  const items: BreadcrumbSegment[] = [
    { label: 'Dashboard', path: '/statistics' },
  ];

  if (path === '/' || path === '/statistics') {
    items.push({ label: 'Statistics', isLast: true });
    return items;
  }

  if (path.startsWith('/sites')) {
    items.push({ label: 'Applications', path: '/sites', isLast: path === '/sites' });

    const siteId = params.id || (path.startsWith('/sites/') ? path.split('/')[2] : undefined);
    if (siteId) {
      const foundSite = configStore.sites.find((s) => s.id === siteId);
      const siteName = foundSite?.name || foundSite?.hostnames?.[0] || `App ${siteId.slice(0, 8)}`;

      if (path.endsWith('/rules')) {
        items.push({ label: siteName, path: `/sites/${siteId}` });
        items.push({ label: 'Forwarding Rules', isLast: true });
      } else if (path.endsWith('/proxy')) {
        items.push({ label: siteName, path: `/sites/${siteId}` });
        items.push({ label: 'Advanced Settings', isLast: true });
      } else if (path.endsWith('/inventory')) {
        items.push({ label: siteName, path: `/sites/${siteId}` });
        items.push({ label: 'API Inventory', isLast: true });
      } else {
        items.push({ label: siteName, isLast: true });
      }
    }
    return items;
  }

  if (path.startsWith('/attacks') || path.startsWith('/inspector')) {
    const isLogs = query.tab === 'logs';
    const isIncidents = query.tab === 'incidents' || query.view === 'incidents';
    const hasSub = isLogs || isIncidents;
    items.push({ label: 'Attacks', path: '/attacks', isLast: !hasSub });
    if (isLogs) {
      items.push({ label: 'Forensic Security Logs', isLast: true });
    } else if (isIncidents) {
      items.push({ label: 'Incident Radar', isLast: true });
    }
    return items;
  }

  if (path.startsWith('/allow-deny') || path.startsWith('/acls')) {
    items.push({ label: 'Allow & Deny', isLast: true });
    return items;
  }

  if (path.startsWith('/http-flood')) {
    items.push({ label: 'HTTP Flood', path: '/http-flood/limits' });
    if (path.includes('waiting-room')) {
      items.push({ label: 'Waiting Room', isLast: true });
    } else if (path.includes('settings')) {
      items.push({ label: 'Rate Limiting', path: '/http-flood/limits' });
      items.push({ label: 'Settings', isLast: true });
    } else {
      items.push({ label: 'Rate Limiting', isLast: true });
    }
    return items;
  }

  if (path.startsWith('/anti-bot')) {
    items.push({ label: 'Anti-Bot', isLast: true });
    return items;
  }

  if (
    path.startsWith('/detection') ||
    path.startsWith('/semantics') ||
    path.startsWith('/inner-rules') ||
    path.startsWith('/exceptions') ||
    path === '/rules'
  ) {
    items.push({ label: 'Detection', path: '/detection' });
    if (path.startsWith('/detection/rules') || path.startsWith('/inner-rules')) {
      items.push({ label: 'Rule Catalog', isLast: true });
    } else if (path.startsWith('/detection/packs')) {
      items.push({ label: 'Rule Packs', isLast: true });
    } else if (path.startsWith('/detection/modules') || path.startsWith('/semantics')) {
      items.push({ label: 'Semantic Matrix', isLast: true });
    } else if (path.startsWith('/detection/exceptions') || path.startsWith('/exceptions')) {
      items.push({ label: 'Exceptions', isLast: true });
    } else if (path.startsWith('/detection/tester')) {
      items.push({ label: 'Rule Tester', isLast: true });
    } else {
      items.push({ label: 'Overview & Policy', isLast: true });
    }
    return items;
  }

  if (path.startsWith('/block-pages') || path.startsWith('/templates')) {
    items.push({ label: 'Block Pages', isLast: true });
    return items;
  }

  if (path.startsWith('/auth-gateway')) {
    items.push({ label: 'Auth Gateway', path: '/auth-gateway/logs' });
    if (path.includes('users')) {
      items.push({ label: 'User Management', isLast: true });
    } else if (path.includes('sso')) {
      items.push({ label: 'Single Sign-On', isLast: true });
    } else if (path.includes('idp')) {
      items.push({ label: 'Login Configuration', isLast: true });
    } else {
      items.push({ label: 'Authentication Logs', isLast: true });
    }
    return items;
  }

  if (path.startsWith('/deployments') || path.startsWith('/snapshots')) {
    items.push({ label: 'Deployments', isLast: true });
    return items;
  }

  if (path.startsWith('/system') || path.startsWith('/settings') || path.startsWith('/auth')) {
    items.push({ label: 'Settings', isLast: true });
    return items;
  }

  // Generic fallback for any arbitrary route structure
  const segments = path.split('/').filter(Boolean);
  if (segments.length === 0) {
    items.push({ label: 'Overview', isLast: true });
    return items;
  }
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    const label = seg.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
    const isLast = i === segments.length - 1;
    const segPath = '/' + segments.slice(0, i + 1).join('/');
    items.push({ label, path: isLast ? undefined : segPath, isLast });
  }
  return items;
});
</script>

<template>
  <Breadcrumb data-testid="navbar-breadcrumbs" class="min-w-0 max-w-full">
    <BreadcrumbList class="flex-nowrap overflow-hidden text-xs sm:text-sm">
      <template v-for="(item, index) in breadcrumbs" :key="index">
        <BreadcrumbItem class="min-w-0 flex items-center">
          <BreadcrumbPage
            v-if="item.isLast"
            data-testid="breadcrumb-active"
            class="text-foreground font-semibold truncate max-w-[130px] sm:max-w-[200px]"
          >
            {{ item.label }}
          </BreadcrumbPage>

          <BreadcrumbLink
            v-else
            data-testid="breadcrumb-link"
            as="button"
            type="button"
            class="text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1.5 cursor-pointer truncate max-w-[90px] sm:max-w-[150px]"
            @click="navigateTo(item.path)"
          >
            <LayoutDashboard v-if="index === 0" class="w-3.5 h-3.5 shrink-0 hidden sm:inline-block" />
            <span class="truncate">{{ item.label }}</span>
          </BreadcrumbLink>
        </BreadcrumbItem>

        <BreadcrumbSeparator
          v-if="index < breadcrumbs.length - 1"
          class="shrink-0"
        />
      </template>
    </BreadcrumbList>
  </Breadcrumb>
</template>
