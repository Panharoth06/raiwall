import { test, expect } from '@playwright/test';

const views = [
  { path: '#/detection', heading: 'Detection' },
  { path: '#/detection/rules', heading: 'Rule Catalog' },
  { path: '#/detection/packs', heading: 'Rule Packs' },
  { path: '#/detection/modules', heading: 'Semantic Detection Matrix' },
  { path: '#/detection/exceptions', heading: 'False-Positive Exception Rules' },
  { path: '#/detection/tester', heading: 'Rule Tester' },
];

const viewports = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
];

test.describe('Detection workspace responsive gate', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('#/login');
    if (await page.locator('input[type="password"]').isVisible()) {
      await page.fill('input[placeholder="Username"]', 'admin');
      await page.fill('input[type="password"]', 'admin');
      await page.click('button[type="submit"]');
      await page.waitForTimeout(600);
    }
  });

  for (const viewport of viewports) {
    test(`${viewport.name} renders every detection view without page overflow`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });

      for (const view of views) {
        await page.goto(view.path);
        await page.waitForTimeout(400);
        await expect(page.locator('h1')).toContainText(view.heading);

        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth
        );
        expect(overflow, `${view.path} overflows the page at ${viewport.width}px`).toBeLessThanOrEqual(1);
      }
    });
  }
});
