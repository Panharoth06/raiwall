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
    await page.goto('#/http-flood');
    await page.waitForLoadState('networkidle');

    // Verify page header
    await expect(page.locator('h1', { hasText: 'Volumetric Defense' })).toBeVisible();

    // Verify 3-Tier Protection Status & Metrics Strip is present
    await expect(page.getByText('Tier 1: Access Velocity')).toBeVisible();
    await expect(page.getByText('Tier 2: Attack Frequency')).toBeVisible();
    await expect(page.getByText('Tier 3: Scanner Trap')).toBeVisible();
    await expect(page.getByText('Active Client Bans', { exact: true })).toBeVisible();

    // Verify metric values are rendered
    await expect(page.getByText('req/min')).toBeVisible();
    await expect(page.getByText('viol/min')).toBeVisible();
    await expect(page.getByText('errs/30s')).toBeVisible();

    // Verify sub-tabs exist
    const tabs = page.locator('[data-testid="tab-item"]');
    await expect(tabs.filter({ hasText: 'Active Blocked Clients' })).toBeVisible();
    await expect(tabs.filter({ hasText: '3-Tier Limits Configuration' })).toBeVisible();
    await expect(tabs.filter({ hasText: 'Waiting Room Dashboard' })).toBeVisible();

    // Switch to 3-Tier Limits Configuration tab
    await tabs.filter({ hasText: '3-Tier Limits Configuration' }).click();
    await expect(page.locator('text=Tier 1: Access Velocity Limiting (Token Bucket)')).toBeVisible();
    await expect(page.locator('input[type="number"]').first()).toBeVisible();

    // Switch to Waiting Room Dashboard tab
    await tabs.filter({ hasText: 'Waiting Room Dashboard' }).click();
    await expect(page.locator('text=Virtual Waiting Room Engine (HTTP 465)')).toBeVisible();

    // Switch back to Active Blocked Clients tab
    await tabs.filter({ hasText: 'Active Blocked Clients' }).click();
    await expect(page.locator('text=Target Client').or(page.locator('text=No active client bans'))).toBeVisible();
  });
});
