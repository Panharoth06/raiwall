import { test, expect } from '@playwright/test';

test.describe('WAF Command Center Dashboard E2E', () => {
  // Test 1: Viewport Lock (Zero Scrollbars) at 1440x900
  test('enforces strict viewport lock with zero vertical or horizontal scrollbars at 1440x900', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="waf-dashboard-root"]');

    const dimensions = await page.evaluate(() => ({
      scrollHeight: document.documentElement.scrollHeight,
      scrollWidth: document.documentElement.scrollWidth,
      innerHeight: window.innerHeight,
      innerWidth: window.innerWidth,
    }));

    expect(dimensions.scrollHeight).toBeLessThanOrEqual(dimensions.innerHeight);
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.innerWidth);
  });

  // Test 2: SVG Cubic Bézier Integrity
  test('verifies all sankey ribbons have valid cubic bezier paths and zero NaN coordinates', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="sankey-ribbon"]');

    const ribbons = page.locator('[data-testid="sankey-ribbon"]');
    const count = await ribbons.count();
    expect(count).toBeGreaterThan(0);

    const bezierRegex = /^M\s*[\d.]+\s*[\d.]+\s*C/;

    for (let i = 0; i < count; i++) {
      const d = await ribbons.nth(i).getAttribute('d');
      expect(d).not.toBeNull();
      expect(d!).toMatch(bezierRegex);
      expect(d!).not.toContain('NaN');
      expect(d!).not.toContain('undefined');
    }
  });

  // Test 3: Interactive Filter & Hub Hover Flow
  test('handles interactive filter toggle and scales hub-waf-core on hover', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="filter-trigger-btn"]');

    // Initial check: filter button says Filters
    const filterBtn = page.locator('[data-testid="filter-trigger-btn"]');
    await expect(filterBtn).toHaveText(/Filters/);

    // Open filter popover
    await filterBtn.click();
    await page.waitForSelector('[data-testid="owasp-filter-switch"]');

    // Toggle OWASP filter
    await page.locator('[data-testid="owasp-filter-switch"]').click();

    // Verify Filters: 1 badge
    await expect(filterBtn).toHaveText(/Filters:\s*1/);

    // Measure initial bounding box of hub-waf-core
    const hub = page.locator('[data-testid="hub-waf-core"]');
    const initialBox = await hub.boundingBox();
    expect(initialBox).not.toBeNull();

    // Hover hub-waf-core
    await hub.hover();
    await page.waitForTimeout(400);

    // Measure hovered bounding box
    const hoveredBox = await hub.boundingBox();
    expect(hoveredBox).not.toBeNull();

    // Verify bounding box scales smoothly
    expect(hoveredBox!.width).toBeGreaterThan(initialBox!.width);
    expect(hoveredBox!.height).toBeGreaterThan(initialBox!.height);
  });
});
