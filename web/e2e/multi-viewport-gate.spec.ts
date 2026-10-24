import { test, expect, type Page } from '@playwright/test';

const viewports = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
];

const routes = [
  '/statistics',
  '/sites',
  '/attacks',
  '/allow-deny',
  '/http-flood/limits',
  '/anti-bot',
  '/semantics',
  '/auth-gateway',
];

async function login(page: Page) {
  await page.goto('#/login');
  const password = page.locator('input[type="password"]');
  if (await password.isVisible().catch(() => false)) {
    await page.fill('input[placeholder="Username"]', 'admin');
    await password.fill('admin');
    await page.locator('button[type="submit"]').first().click();
    await page.waitForTimeout(600);
  }
}

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  );
  expect(overflow).toBeLessThanOrEqual(2);
}

for (const vp of viewports) {
  test.describe(`responsive gate ${vp.name} ${vp.width}x${vp.height}`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } });

    test(`renders every control-plane view without overflow (${vp.name})`, async ({ page }) => {
      await login(page);

      if (vp.width < 1024) {
        // The sidebar becomes an off-canvas drawer on tablet and mobile.
        const rail = page.locator('[data-testid="nav-rail"]');
        await page.locator('[data-testid="nav-mobile-toggle"]').click();
        await page.waitForTimeout(250);
        const openBox = await rail.boundingBox();
        expect(openBox).not.toBeNull();
        expect(openBox!.x).toBeGreaterThanOrEqual(0);

        await page.locator('[data-testid="nav-mobile-close"]').click();
        await page.waitForTimeout(250);
        const closedBox = await rail.boundingBox();
        expect(closedBox).not.toBeNull();
        expect(closedBox!.x + closedBox!.width).toBeLessThanOrEqual(1);
      }

      for (const route of routes) {
        await page.goto(`#${route}`);
        await page.waitForTimeout(250);
        await expectNoHorizontalOverflow(page);

        const bodyText = (await page.locator('body').innerText()).trim();
        expect(bodyText.length).toBeGreaterThan(20);
        expect(bodyText).not.toContain('Internal Server Error');
        expect(bodyText).not.toContain('Cannot read properties');
      }
    });

    test(`anti-bot policy and override dialog remain usable (${vp.name})`, async ({ page }) => {
      await login(page);
      await page.goto('#/anti-bot');

      await expect(page.locator('[data-testid="bot-policy-card"]')).toBeVisible();
      await expect(page.locator('[data-testid="bot-host-card"]')).toBeVisible();
      await expect(page.locator('[data-testid="bot-activity-card"]')).toBeVisible();
      await expectNoHorizontalOverflow(page);

      await page.locator('[data-testid="bot-add-host"]').click();
      const dialog = page.locator('[data-testid="bot-host-dialog"]');
      await expect(dialog).toBeVisible();

      const box = await dialog.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.width).toBeLessThanOrEqual(vp.width);

      await page.locator('[data-testid="bot-cancel-host"]').click();
      await expect(dialog).toHaveCount(0);
    });

    test(`incident drill-down and forensic drawer work (${vp.name})`, async ({ page }) => {
      await login(page);
      await page.goto('#/attacks');
      await page.waitForSelector('[data-testid="view-tab-incidents"]');

      await page.locator('[data-testid="view-tab-incidents"]').click();
      const cards = page.locator('[data-testid="incident-card"]');
      await expect(cards.first()).toBeVisible({ timeout: 10000 });

      await cards.first().click();
      await page.waitForSelector('[data-testid="event-row"]', { timeout: 10000 });
      await expect(page.locator('[data-testid="host-filter-chip"]')).toBeVisible();

      await page.locator('[data-testid="event-row"]').first().click();
      const drawer = page.locator('[data-testid="forensic-modal"]');
      await expect(drawer).toBeVisible();

      await expect(page.locator('[data-testid="payload-location"]')).toBeVisible();
      await expect(page.locator('[data-testid="drawer-tab-request"]')).toBeVisible();
      await page.locator('[data-testid="drawer-tab-response"]').click();
      await expect(page.locator('[data-testid="encoding-select"]')).toHaveCount(0);
      await page.locator('[data-testid="drawer-tab-request"]').click();
      await expect(page.locator('[data-testid="encoding-select"]')).toBeVisible();

      await expectNoHorizontalOverflow(page);

      await page.locator('[data-testid="modal-close-btn"]').click();
      await expect(drawer).toHaveCount(0);
    });
  });
}
