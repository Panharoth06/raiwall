import { test, expect } from '@playwright/test';

test.describe('Telemetry Persistence and HTTP Flood View E2E', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('#/login');
    if (await page.locator('input[type="password"]').isVisible()) {
      await page.fill('input[placeholder="Username"]', 'admin');
      await page.fill('input[type="password"]', 'admin');
      await page.click('button[type="submit"]');
      await page.waitForTimeout(600);
    }
  });

  test('1. Live Telemetry loads historical attacks and persists across route navigation', async ({ page }) => {
    // Navigate directly to attacks view
    await page.goto('#/attacks');
    await page.waitForLoadState('networkidle');

    // Wait for event rows to be populated (from SQLite history or stream)
    const eventRows = page.locator('[data-testid="event-row"]');
    await expect(eventRows.first()).toBeVisible({ timeout: 10000 });
    const countBefore = await eventRows.count();
    expect(countBefore).toBeGreaterThan(0);

    // Verify row content contains IP
    const firstRowText = await eventRows.first().textContent();
    expect(firstRowText).toContain('192.168.');

    // Navigate to another view using sidebar (e.g. Protected Sites / Applications)
    const sitesBtn = page.locator('[data-testid="nav-applications"]');
    await sitesBtn.click();
    await page.waitForURL('**/.raiwall/#/sites');
    await expect(page.locator('h1', { hasText: 'Protected Sites' })).toBeVisible();

    // Navigate back to Live Telemetry
    const attacksBtn = page.locator('[data-testid="nav-attacks"]');
    await attacksBtn.click();
    await page.waitForURL('**/.raiwall/#/attacks');

    // Verify events are STILL present and did NOT disappear!
    await expect(eventRows.first()).toBeVisible({ timeout: 5000 });
    const countAfter = await eventRows.count();
    expect(countAfter).toBeGreaterThanOrEqual(countBefore);
  });

  test('2. HTTP Flood view displays 3-tier metrics overview and ban registry cleanly', async ({ page }) => {
    // Navigate to HTTP Flood view
    await page.goto('#/http-flood/limits');
    await page.waitForLoadState('networkidle');

    // Verify page header
    await expect(page.locator('h1', { hasText: 'HTTP Flood & Rate Limiting Defense' })).toBeVisible();

    // Verify the active ban registry table headers
    await expect(page.locator('th', { hasText: 'IP Addr' })).toBeVisible();
    await expect(page.locator('th', { hasText: 'Detail' })).toBeVisible();
    await expect(page.locator('th', { hasText: 'Blocked' })).toBeVisible();
    await expect(page.locator('th', { hasText: 'Action' })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();

    // Verify sub-tabs exist
    await expect(page.locator('[data-testid="tab-http-flood-limits"]')).toBeVisible();
    await expect(page.locator('[data-testid="tab-http-flood-waiting-room"]')).toBeVisible();

    // Switch to Waiting Room tab
    await page.locator('[data-testid="tab-http-flood-waiting-room"]').click();
    await page.waitForURL('**/#/http-flood/waiting-room');
    await expect(page.locator('h2', { hasText: 'Virtual Waiting Room Engine' })).toHaveCount(1);
    await expect(page.getByRole('button', { name: 'SETTINGS', exact: true })).toBeVisible();

    // Switch back to Rate Limiting tab
    await page.locator('[data-testid="tab-http-flood-limits"]').click();
    await expect(page.locator('th', { hasText: 'IP Addr' })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();
  });
});
