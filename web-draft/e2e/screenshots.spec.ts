import { test } from '@playwright/test';

test.describe('WAF Command Center Visual Verification Screenshots', () => {
  test('capture all key states at 1440x900', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });

    // 1. Default Traffic View
    await page.goto('/');
    await page.waitForSelector('[data-testid="waf-dashboard-root"]');
    await page.waitForTimeout(500);
    await page.screenshot({ path: 'screenshots/01-traffic-default-1440x900.png' });

    // 2. Human Clients Expanded View
    await page.locator('[data-testid="source-node-humans"]').click();
    await page.waitForSelector('[data-testid="subnode-verified"]');
    await page.waitForTimeout(300);
    await page.screenshot({ path: 'screenshots/02-traffic-humans-expanded-1440x900.png' });

    // 3. Filter Popover Open & OWASP Filter Activated
    const filterBtn = page.locator('[data-testid="filter-trigger-btn"]');
    await filterBtn.click();
    await page.waitForSelector('[data-testid="owasp-filter-switch"]');
    await page.locator('[data-testid="owasp-filter-switch"]').click();
    await page.waitForTimeout(300);
    await page.screenshot({ path: 'screenshots/03-owasp-filter-active-1440x900.png' });

    // Close popover
    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);

    // 4. Hub Hover (WAF Core Engine starburst spikes expanded)
    await page.locator('[data-testid="hub-waf-core"]').hover();
    await page.waitForTimeout(400);
    await page.screenshot({ path: 'screenshots/04-hub-waf-core-hover-1440x900.png' });

    // 5. Arc Node Tooltip Active
    const arcNode = page.locator('[data-testid="arc-node-item"]').first();
    await arcNode.hover();
    await page.waitForSelector('[data-testid="topology-tooltip"]');
    await page.waitForTimeout(300);
    await page.screenshot({ path: 'screenshots/05-arc-node-tooltip-1440x900.png' });

    // 6. Threats Mode
    await page.locator('[data-testid="mode-btn-threats"]').click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: 'screenshots/06-threats-mode-1440x900.png' });
  });

  test('capture default view at 1920x1080', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/');
    await page.waitForSelector('[data-testid="waf-dashboard-root"]');
    await page.waitForTimeout(500);
    await page.screenshot({ path: 'screenshots/07-traffic-default-1920x1080.png' });
  });
});
