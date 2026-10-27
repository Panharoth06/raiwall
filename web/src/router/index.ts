import { ref, shallowRef, h, defineComponent, inject, type App, type Component, type Plugin } from 'vue';

export interface RouteRecord {
  path: string;
  name: string;
  component: Component | (() => Promise<{ default: Component }>);
  meta?: {
    requiresAuth?: boolean;
    requiresAdmin?: boolean;
    title?: string;
  };
}

export interface RouteLocation {
  path: string;
  fullPath: string;
  name: string;
  params: Record<string, string>;
  query: Record<string, string>;
}

export type NavigationGuard = (
  to: RouteLocation,
  from: RouteLocation,
  next: (target?: string | boolean) => void
) => void | Promise<void>;

const ROUTER_KEY = Symbol('ROUTER_KEY');
const CURRENT_ROUTE_KEY = Symbol('CURRENT_ROUTE_KEY');

export class SimpleRouter {
  private routes: RouteRecord[] = [];
  private guards: NavigationGuard[] = [];
  public current = ref<RouteLocation>({
    path: '/',
    fullPath: '/',
    name: 'overview',
    params: {},
    query: {},
  });
  public activeComponent = shallowRef<Component | null>(null);

  constructor(routes: RouteRecord[]) {
    this.routes = routes;
    if (typeof window !== 'undefined') {
      const initial = window.location.hash ? window.location.hash.slice(1) : '/';
      this.navigate(initial || '/');
      window.addEventListener('hashchange', () => {
        const hash = window.location.hash ? window.location.hash.slice(1) : '/';
        const parsed = this.parseTarget(hash);
        if (this.current.value.fullPath !== parsed.fullPath) {
          this.navigate(hash);
        }
      });
    }
  }

  public parseTarget(target: string): { pathname: string; fullPath: string; query: Record<string, string> } {
    let raw = target.startsWith('#') ? target.slice(1) : target;
    if (!raw.startsWith('/')) {
      raw = '/' + raw;
    }
    const [pathname, search] = raw.split('?');
    const query: Record<string, string> = {};
    if (search) {
      const searchParams = new URLSearchParams(search);
      searchParams.forEach((val, key) => {
        query[key] = val;
      });
    }
    return {
      pathname: pathname || '/',
      fullPath: raw,
      query,
    };
  }

  private matchRoute(pathname: string): { route: RouteRecord; params: Record<string, string> } | undefined {
    // 1. Exact match first
    const exact = this.routes.find((r) => r.path === pathname);
    if (exact) {
      return { route: exact, params: {} };
    }

    // 2. Dynamic parameterized segments e.g. /sites/:id
    const pathParts = pathname.split('/').filter(Boolean);
    for (const r of this.routes) {
      if (r.path.includes(':')) {
        const routeParts = r.path.split('/').filter(Boolean);
        if (routeParts.length === pathParts.length) {
          let matches = true;
          const params: Record<string, string> = {};
          for (let i = 0; i < routeParts.length; i++) {
            if (routeParts[i].startsWith(':')) {
              params[routeParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
            } else if (routeParts[i] !== pathParts[i]) {
              matches = false;
              break;
            }
          }
          if (matches) {
            return { route: r, params };
          }
        }
      }
    }

    // 3. Fallback to /
    const fallback = this.routes.find((r) => r.path === '/');
    if (fallback) {
      return { route: fallback, params: {} };
    }
    return undefined;
  }

  public beforeEach(guard: NavigationGuard) {
    this.guards.push(guard);
  }

  public async push(path: string) {
    const parsed = this.parseTarget(path);
    if (typeof window !== 'undefined') {
      window.location.hash = parsed.fullPath;
    }
    await this.navigate(path);
  }

  public async replace(path: string) {
    await this.push(path);
  }

  public async navigate(target: string) {
    const { pathname, fullPath, query } = this.parseTarget(target);
    const matched = this.matchRoute(pathname);
    const routeRecord = matched?.route;
    const params = matched?.params || {};

    const targetRoute: RouteLocation = {
      path: pathname,
      fullPath,
      name: routeRecord?.name || 'unknown',
      params,
      query,
    };

    const fromRoute = { ...this.current.value };

    // Execute guards sequentially
    for (const guard of this.guards) {
      let redirectedTarget: string | boolean | undefined;
      const next = (dest?: string | boolean) => {
        redirectedTarget = dest;
      };

      await guard(targetRoute, fromRoute, next);

      if (redirectedTarget === false) {
        return;
      }
      if (typeof redirectedTarget === 'string' && redirectedTarget !== fullPath && redirectedTarget !== pathname) {
        await this.push(redirectedTarget);
        return;
      }
    }

    this.current.value = targetRoute;

    if (routeRecord) {
      if (typeof routeRecord.component === 'function') {
        const loaded = await (routeRecord.component as () => Promise<{ default: Component }>)();
        this.activeComponent.value = loaded.default || loaded;
      } else {
        this.activeComponent.value = routeRecord.component;
      }
    }
  }

  public install(app: App) {
    app.provide(ROUTER_KEY, this);
    app.provide(CURRENT_ROUTE_KEY, this.current);

    const router = this;
    app.component('RouterView', defineComponent({
      name: 'RouterView',
      setup() {
        return () => (router.activeComponent.value ? h(router.activeComponent.value) : null);
      },
    }));

    app.config.globalProperties.$router = this;
    app.config.globalProperties.$route = this.current;
  }
}

let defaultRouter: SimpleRouter | null = null;

export function useRouter(): SimpleRouter {
  const router = inject<SimpleRouter>(ROUTER_KEY, null as any);
  if (router) {
    return router;
  }
  if (defaultRouter) {
    return defaultRouter;
  }
  return new SimpleRouter([]);
}

export function useRoute() {
  const route = inject<typeof SimpleRouter.prototype.current>(CURRENT_ROUTE_KEY, null as any);
  if (route) {
    return route;
  }
  if (defaultRouter) {
    return defaultRouter.current;
  }
  return ref<RouteLocation>({ path: '/', fullPath: '/', name: 'overview', params: {}, query: {} });
}

export function createSimpleRouter(routes: RouteRecord[]): SimpleRouter & Plugin {
  const r = new SimpleRouter(routes);
  defaultRouter = r;
  return r;
}

// Router instance with all routes for Raiwall Control Plane
import CommandCenterView from '@/views/CommandCenterView.vue';
import StatisticsView from '@/views/StatisticsView.vue';
import AttacksView from '@/views/AttacksView.vue';
import LoginView from '@/views/LoginView.vue';
import SitesView from '@/views/SitesView.vue';
import SiteDetailView from '@/views/SiteDetailView.vue';
import ExceptionsView from '@/views/ExceptionsView.vue';
import ACLsView from '@/views/ACLsView.vue';
import AntiBotView from '@/views/AntiBotView.vue';
import HttpFloodView from '@/views/HttpFloodView.vue';
import SettingsView from '@/views/SettingsView.vue';
import DeploymentsView from '@/views/DeploymentsView.vue';
import RulesView from '@/views/RulesView.vue';
import BlockPagesView from '@/views/BlockPagesView.vue';
import SemanticsView from '@/views/SemanticsView.vue';
import InnerRulesView from '@/views/InnerRulesView.vue';
import AuthGatewayView from '@/views/AuthGatewayView.vue';

export const router = createSimpleRouter([
  { path: '/', name: 'statistics', component: StatisticsView },
  { path: '/statistics', name: 'statistics-alias', component: StatisticsView },
  { path: '/topology', name: 'topology', component: CommandCenterView },
  { path: '/command-center', name: 'command-center', component: CommandCenterView },
  { path: '/sites', name: 'sites', component: SitesView },
  { path: '/sites/:id', name: 'site-detail', component: SiteDetailView },
  { path: '/sites/:id/rules', name: 'site-detail-rules', component: SiteDetailView },
  { path: '/sites/:id/proxy', name: 'site-detail-proxy', component: SiteDetailView },
  { path: '/sites/:id/inventory', name: 'site-detail-inventory', component: SiteDetailView },
  { path: '/attacks', name: 'attacks', component: AttacksView },
  { path: '/inspector', name: 'inspector', component: AttacksView },
  { path: '/allow-deny', name: 'allow-deny', component: ACLsView },
  { path: '/acls', name: 'acls', component: ACLsView },
  { path: '/http-flood', name: 'http-flood', component: HttpFloodView },
  { path: '/http-flood/limits', name: 'http-flood-limits', component: HttpFloodView },
  { path: '/http-flood/limits/settings', name: 'http-flood-settings', component: HttpFloodView },
  { path: '/http-flood/waiting-room', name: 'http-flood-waiting-room', component: HttpFloodView },
  { path: '/auth-gateway', name: 'auth-gateway', component: AuthGatewayView },
  { path: '/auth-gateway/logs', name: 'auth-gateway-logs', component: AuthGatewayView },
  { path: '/auth-gateway/users', name: 'auth-gateway-users', component: AuthGatewayView },
  { path: '/auth-gateway/sso', name: 'auth-gateway-sso', component: AuthGatewayView },
  { path: '/auth-gateway/idp', name: 'auth-gateway-idp', component: AuthGatewayView },
  { path: '/anti-bot', name: 'anti-bot', component: AntiBotView },
  { path: '/block-pages', name: 'block-pages', component: BlockPagesView },
  { path: '/templates', name: 'templates', component: BlockPagesView },
  { path: '/auth', name: 'auth', component: SettingsView },
  { path: '/system', name: 'system', component: SettingsView },
  { path: '/settings', name: 'settings', component: SettingsView },
  { path: '/rules', name: 'rules', component: RulesView },
  { path: '/exceptions', name: 'exceptions', component: ExceptionsView },
  { path: '/semantics', name: 'semantics', component: SemanticsView },
  { path: '/inner-rules', name: 'inner-rules', component: InnerRulesView },
  { path: '/deployments', name: 'deployments', component: DeploymentsView },
  { path: '/snapshots', name: 'snapshots', component: DeploymentsView },
  { path: '/login', name: 'login', component: LoginView },
]);

export default router;
