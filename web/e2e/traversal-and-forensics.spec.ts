import { test, expect } from '@playwright/test';

test.describe('Path Traversal & Telemetry Forensics Modal Verification', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('#/login');
    if (await page.locator('input[type="password"]').isVisible()) {
      await page.fill('input[placeholder="Username"]', 'admin');
      await page.fill('input[type="password"]', 'admin');
      await page.click('button[type="submit"]');
      await page.waitForTimeout(500);
    }
  });

  test('verifies path traversal blocking and forensic modal distinction between allow and block', async ({ page }) => {
    // 1. Send benign request to ensure allow event exists in telemetry
    const benignRes = await page.request.get('http://127.0.0.1:8080/public/download?file=readme.txt', {
      headers: { 'Accept': 'application/json' },
    });
    expect(benignRes.status()).toBe(200);

    // 2. Send path traversal attack to ensure block event exists in telemetry
    const attackRes = await page.request.get('http://127.0.0.1:8080/public/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd', {
      headers: { 'Accept': 'application/json' },
    });
    expect(attackRes.status()).toBe(403);

    // 3. Navigate to Attacks forensic inspector
    await page.goto('#/attacks');
    await page.waitForSelector('table');
    await page.waitForTimeout(600);

    // 4. Locate table rows for blocked threat and allowed benign traffic
    const blockRow = page.locator('tr[data-testid="event-row"]:has-text("TRAVERSAL")').first();
    const allowRow = page.locator('tr[data-testid="event-row"]:has-text("readme.txt")').first();

    await expect(blockRow).toBeVisible();
    await expect(allowRow).toBeVisible();

    // Verify quick action button "Exception" is NOT visible on the allow row
    await expect(allowRow.locator('[data-testid="create-exception-quick-btn"]')).not.toBeVisible();
    // But IS visible on the block row
    await expect(blockRow.locator('[data-testid="create-exception-quick-btn"]')).toBeVisible();

    // 5. Open Modal for BLOCKED threat row
    await blockRow.click();
    await page.waitForSelector('[data-testid="forensic-modal"]');
    
    // Header should say "Forensic Incident Context"
    await expect(page.locator('text=Forensic Incident Context')).toBeVisible();
    // "Create Exception" button SHOULD be present for blocked threats
    await expect(page.locator('[data-testid="modal-create-exception-btn"]')).toBeVisible();

    // Close modal via close button
    await page.locator('[data-testid="modal-close-btn"]').click();
    await page.waitForSelector('[data-testid="forensic-modal"]', { state: 'detached' });

    // 6. Open Modal for ALLOW benign row
    await allowRow.click();
    await page.waitForSelector('[data-testid="forensic-modal"]');

    // Header should say "Traffic Telemetry Context"
    await expect(page.locator('text=Traffic Telemetry Context')).toBeVisible();
    // "Create Exception" button should NOT be present for allowed benign traffic
    await expect(page.locator('[data-testid="modal-create-exception-btn"]')).not.toBeVisible();

    // Verify parameter location badge and query string are shown in the drawer
    await expect(page.locator('[data-testid="payload-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="forensic-modal"] pre:has-text("file=readme.txt")')).toBeVisible();

    // Close modal
    await page.locator('[data-testid="modal-close-btn"]').click();
  });
});
