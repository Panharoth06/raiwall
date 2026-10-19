import { ref, computed, shallowRef, h, defineComponent, inject, type App, type Component, type Plugin } from 'vue';

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
    name: 'overview',
    params: {},
    query: {},
  });
  public activeComponent = shallowRef<Component | null>(null);

  constructor(routes: RouteRecord[]) {
    this.routes = routes;
    if (typeof window !== 'undefined') {
      const initialPath = window.location.hash ? window.location.hash.slice(1) : '/';
      this.navigate(initialPath || '/');
      window.addEventListener('hashchange', () => {
        const path = window.location.hash.slice(1) || '/';
        if (this.current.value.path !== path) {
          this.navigate(path);
        }
      });
    }
  }

  public beforeEach(guard: NavigationGuard) {
    this.guards.push(guard);
  }

  public async push(path: string) {
    if (typeof window !== 'undefined') {
      window.location.hash = path;
    }
    await this.navigate(path);
  }

  public async replace(path: string) {
    await this.push(path);
  }

  private matchRoute(path: string): RouteRecord | undefined {
    return this.routes.find((r) => r.path === path) || this.routes.find((r) => r.path === '/');
  }

  public async navigate(path: string) {
    const matched = this.matchRoute(path);
    const targetRoute: RouteLocation = {
      path,
      name: matched?.name || 'unknown',
      params: {},
      query: {},
    };

    const fromRoute = { ...this.current.value };

    // Execute guards sequentially
    for (const guard of this.guards) {
      let redirectedTarget: string | boolean | undefined;
      let nextCalled = false;

      const next = (target?: string | boolean) => {
        nextCalled = true;
        redirectedTarget = target;
      };

      await guard(targetRoute, fromRoute, next);

      if (redirectedTarget === false) {
        return;
      }
      if (typeof redirectedTarget === 'string' && redirectedTarget !== path) {
        await this.push(redirectedTarget);
        return;
      }
    }

    this.current.value = targetRoute;

    if (matched) {
      if (typeof matched.component === 'function') {
        const loaded = await (matched.component as () => Promise<{ default: Component }>)();
        this.activeComponent.value = loaded.default || loaded;
      } else {
        this.activeComponent.value = matched.component;
      }
    }
  }

  public install(app: App) {
    app.provide(ROUTER_KEY, this);
    app.provide(CURRENT_ROUTE_KEY, this.current);

    app.component('RouterView', defineComponent({
      name: 'RouterView',
      setup() {
        return () => (this.router.activeComponent.value ? h(this.router.activeComponent.value) : null);
      },
      data() {
        return { router: this.$router };
      },
    }));

    app.config.globalProperties.$router = this;
    app.config.globalProperties.$route = this.current;
  }
}

export function useRouter(): SimpleRouter {
  const router = inject<SimpleRouter>(ROUTER_KEY);
  if (!router) {
    throw new Error('useRouter() called outside of router context');
  }
  return router;
}

export function useRoute() {
  const route = inject<typeof SimpleRouter.prototype.current>(CURRENT_ROUTE_KEY);
  if (!route) {
    return ref<RouteLocation>({ path: '/', name: 'overview', params: {}, query: {} });
  }
  return route;
}

export function createSimpleRouter(routes: RouteRecord[]): SimpleRouter & Plugin {
  return new SimpleRouter(routes);
}

// Router instance with all routes for Raiwall Control Plane
import WafCommandCenter from '@/components/WafCommandCenter.vue';
import LoginView from '@/views/LoginView.vue';
import SitesView from '@/views/SitesView.vue';
import ExceptionsView from '@/views/ExceptionsView.vue';
import ACLsView from '@/views/ACLsView.vue';
import PoliciesView from '@/views/PoliciesView.vue';
import SettingsView from '@/views/SettingsView.vue';
import DeploymentsView from '@/views/DeploymentsView.vue';

export const router = createSimpleRouter([
  { path: '/', name: 'overview', component: WafCommandCenter },
  { path: '/login', name: 'login', component: LoginView },
  { path: '/sites', name: 'sites', component: SitesView },
  { path: '/exceptions', name: 'exceptions', component: ExceptionsView },
  { path: '/acls', name: 'acls', component: ACLsView },
  { path: '/policies', name: 'policies', component: PoliciesView },
  { path: '/settings', name: 'settings', component: SettingsView },
  { path: '/deployments', name: 'deployments', component: DeploymentsView },
]);

export default router;
