import { test, expect, type Page } from '@playwright/test';

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

test('statistics KPI cards reflect the aggregate API', async ({ page }) => {
  await login(page);
  await page.goto('#/statistics');
  await expect(page.getByTestId('metric-requests')).toBeVisible();
  await expect(page.getByTestId('metric-page-views')).not.toHaveText('0', { timeout: 10_000 });

  const response = await page.request.get('api/v1/telemetry/events/stats');
  expect(response.ok()).toBeTruthy();
  const stats = await response.json();

  const expected: Record<string, number> = {
    'metric-requests': stats.total_requests,
    'metric-page-views': stats.page_views,
    'metric-unique-visitors': stats.unique_visitors,
    'metric-unique-ips': stats.unique_ips,
    'metric-blocked': stats.total_blocked,
    'metric-blocked-ips': stats.blocked_ips,
  };

  for (const [testID, value] of Object.entries(expected)) {
    await expect(page.getByTestId(testID)).toHaveText(value.toLocaleString());
  }
});
