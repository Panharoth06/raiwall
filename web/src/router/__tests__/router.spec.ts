import { describe, it, expect, beforeEach } from 'vitest';
import { SimpleRouter, type RouteRecord } from '../index';
import { defineComponent, h } from 'vue';

const DummyComponent = defineComponent({
  name: 'DummyComponent',
  render: () => h('div', 'Dummy'),
});

describe('SimpleRouter (Task 73)', () => {
  let router: SimpleRouter;
  const routes: RouteRecord[] = [
    { path: '/', name: 'home', component: DummyComponent },
    { path: '/attacks', name: 'attacks', component: DummyComponent },
    { path: '/sites/:id', name: 'site-detail', component: DummyComponent },
    { path: '/users/:userId/roles/:roleId', name: 'user-role', component: DummyComponent },
  ];

  beforeEach(() => {
    router = new SimpleRouter(routes);
  });

  it('parses hash paths containing query parameters without breaking route matching', async () => {
    await router.navigate('/attacks?tab=log&ip=10.0.0.1');

    expect(router.current.value.path).toBe('/attacks');
    expect(router.current.value.fullPath).toBe('/attacks?tab=log&ip=10.0.0.1');
    expect(router.current.value.name).toBe('attacks');
    expect(router.current.value.query).toEqual({
      tab: 'log',
      ip: '10.0.0.1',
    });
  });

  it('captures dynamic route parameters in params object', async () => {
    await router.navigate('/sites/app-prod-01');

    expect(router.current.value.path).toBe('/sites/app-prod-01');
    expect(router.current.value.name).toBe('site-detail');
    expect(router.current.value.params).toEqual({
      id: 'app-prod-01',
    });
  });

  it('captures multiple dynamic route parameters and query string simultaneously', async () => {
    await router.navigate('/users/usr_42/roles/admin?filter=active');

    expect(router.current.value.path).toBe('/users/usr_42/roles/admin');
    expect(router.current.value.name).toBe('user-role');
    expect(router.current.value.params).toEqual({
      userId: 'usr_42',
      roleId: 'admin',
    });
    expect(router.current.value.query).toEqual({
      filter: 'active',
    });
  });

  it('handles navigation guards with redirection', async () => {
    let guardInvoked = false;
    router.beforeEach((to, from, next) => {
      guardInvoked = true;
      if (to.path === '/attacks') {
        next();
      } else {
        next();
      }
    });

    await router.navigate('/attacks');
    expect(guardInvoked).toBe(true);
    expect(router.current.value.path).toBe('/attacks');
  });
});
