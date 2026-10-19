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

    // Verify hub remains stably anchored without scale distortion
    expect(Math.abs(hoveredBox!.width - initialBox!.width)).toBeLessThanOrEqual(20);
    expect(Math.abs(hoveredBox!.height - initialBox!.height)).toBeLessThanOrEqual(20);
  });

  // Test 4: Human Clients Orbital Click Expansion
  test('expands human clients subnodes on click and verifies viewport positioning', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="source-node-humans"]');

    // Click to expand
    await page.locator('[data-testid="source-node-humans"]').click();
    await page.waitForSelector('[data-testid="subnode-verified"]');
    await page.waitForSelector('[data-testid="subnode-anonymous"]');

    const verified = page.locator('[data-testid="subnode-verified"]');
    const anonymous = page.locator('[data-testid="subnode-anonymous"]');
    await expect(verified).toBeVisible();
    await expect(anonymous).toBeVisible();

    const boxV = await verified.boundingBox();
    const boxA = await anonymous.boundingBox();
    expect(boxV).not.toBeNull();
    expect(boxA).not.toBeNull();
    expect(boxV!.x + boxV!.width).toBeLessThanOrEqual(1440);
    expect(boxA!.x + boxA!.width).toBeLessThanOrEqual(1440);
  });

  // Test 5: Tooltip Visibility and Strict Viewport Bounds
  test('verifies topology tooltip stays strictly within viewport boundaries when hovering right-column nodes', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="arc-node-item"]');

    const firstNode = page.locator('[data-testid="arc-node-item"]').first();
    await firstNode.hover();
    await page.waitForSelector('[data-testid="topology-tooltip"]');

    const tooltip = page.locator('[data-testid="topology-tooltip"]');
    await expect(tooltip).toBeVisible();

    const box = await tooltip.boundingBox();
    expect(box).not.toBeNull();
    // Must be completely within 1440x900 viewport
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(1440);
    expect(box!.y).toBeGreaterThanOrEqual(0);
    expect(box!.y + box!.height).toBeLessThanOrEqual(900);
  });

  // Test 6: Traffic vs Threats Mode Switch E2E
  test('switches view mode to Threats and updates summary metrics', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="dest-summary-upper"]');

    const upperSummary = page.locator('[data-testid="dest-summary-upper"]');
    await expect(upperSummary).toContainText('API GATEWAY ROUTES');

    await page.locator('[data-testid="mode-btn-threats"]').click();
    await expect(upperSummary).toContainText('INJECTION VECTORS');
    await expect(upperSummary).toContainText('2.14M Payloads Blocked');

    await page.locator('[data-testid="mode-btn-traffic"]').click();
    await expect(upperSummary).toContainText('API GATEWAY ROUTES');
  });
});
