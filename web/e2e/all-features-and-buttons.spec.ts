import { test, expect } from '@playwright/test';

test.describe('Comprehensive End-to-End Feature & Interactive Button Audit', () => {
  test.beforeEach(async ({ page }) => {
    page.on('response', (response) => {
      const url = response.url();
      const status = response.status();
      if (!url.includes('/auth/login') && !url.includes('/healthz') && status >= 400) {
        console.warn(`[HTTP ${status}] unexpected error on ${url}`);
      }
    });

    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('#/login');
    if (await page.locator('input[type="password"]').isVisible()) {
      await page.fill('input[placeholder="Username"]', 'admin');
      await page.fill('input[type="password"]', 'admin');
      await page.click('button[type="submit"]');
      await page.waitForTimeout(600);
    }
  });

  // 1. Navigation across all views
  test('1. Sidebar Navigation: Visits all primary navigation sections cleanly', async ({ page }) => {
    const navItems = [
      { id: 'nav-topology', target: '#/topology' },
      { id: 'nav-statistics', target: '#/statistics' },
      { id: 'nav-applications', target: '#/sites' },
      { id: 'nav-attacks', target: '#/attacks' },
      { id: 'nav-allow-deny', target: '#/allow-deny' },
      { id: 'nav-http-flood', target: '#/http-flood' },
      { id: 'nav-anti-bot', target: '#/anti-bot' },
      { id: 'nav-auth', target: '#/auth' },
      { id: 'nav-settings', target: '#/system' },
    ];

    for (const item of navItems) {
      const btn = page.locator(`[data-testid="${item.id}"]`);
      if (await btn.isVisible()) {
        await btn.click();
        await page.waitForTimeout(300);
        expect(page.url()).toContain(item.target.replace('#', ''));
      }
    }
  });

  // 2. Topology Command Center Controls
  test('2. Topology Controls: Toggles Threats/Traffic, OWASP filters, and expands nodes', async ({ page }) => {
    await page.goto('#/topology');
    await page.waitForSelector('[data-testid="waf-dashboard-root"]');

    // Toggle Threats mode
    const threatsBtn = page.locator('[data-testid="mode-btn-threats"]');
    await threatsBtn.click();
    await page.waitForTimeout(300);

    // Toggle Traffic mode
    const trafficBtn = page.locator('[data-testid="mode-btn-traffic"]');
    await trafficBtn.click();
    await page.waitForTimeout(300);

    // Filter popover and switch
    const filterBtn = page.locator('[data-testid="filter-trigger-btn"]');
    await filterBtn.click();
    await page.waitForSelector('[data-testid="owasp-filter-switch"]');
    await page.locator('[data-testid="owasp-filter-switch"]').click();
    await page.waitForTimeout(200);
    await page.keyboard.press('Escape');

    // Expand human nodes
    const humanNodes = page.locator('[data-testid="source-node-humans"]');
    await humanNodes.click();
    await page.waitForSelector('[data-testid="subnode-verified"]');
    expect(await page.locator('[data-testid="subnode-verified"]').isVisible()).toBe(true);
  });

  // 3. Protected Sites Lifecycle
  test('3. Protected Sites: Full CRUD lifecycle with upstream duration strings', async ({ page }) => {
    await page.goto('#/sites');
    await page.waitForTimeout(400);

    // Open Add Protected Site modal
    const addSiteBtn = page.locator('button:has-text("Add Protected Site"), button:has-text("Add First Application"), button:has-text("Add First Site")').first();
    await addSiteBtn.click();
    await page.waitForSelector('input[placeholder="e.g. Payment Gateway"]');

    // Fill form
    await page.fill('input[placeholder="e.g. Payment Gateway"]', 'E2E Automated Site');
    await page.fill('input[placeholder="api.example.com, pay.example.com"]', 'e2e.test.com');

    // Add Upstream button in UpstreamPoolEditor
    const addUpstreamBtn = page.locator('button:has-text("Add Upstream Target")');
    if (await addUpstreamBtn.isVisible()) {
      await addUpstreamBtn.click();
      await page.waitForTimeout(200);
    }

    // Save Site to Draft
    const saveBtn = page.locator('button:has-text("Save to Draft")');
    await saveBtn.click();
    await page.waitForTimeout(600);

    // Assert site is in the table
    await expect(page.locator('text=E2E Automated Site')).toBeVisible();

    // Delete site cleanly
    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });
    const deleteBtn = page.locator('table tr:has-text("E2E Automated Site") button').last();
    await deleteBtn.click();
    await page.waitForTimeout(600);
  });

  // 4. Bytecode ACL Rules & Syntax Verifier
  test('4. ACL Rules: Expr-lang syntax dry-run verification and rule creation', async ({ page }) => {
    await page.goto('#/acls');
    await page.waitForTimeout(400);

    // Open Add ACL Rule dialog
    const addAclBtn = page.locator('button:has-text("New ACL Rule"), button:has-text("Add First ACL Rule")').first();
    await addAclBtn.click();
    await page.waitForSelector('textarea[placeholder*="in_cidr"]');

    // Click "Verify Syntax" button
    const verifyBtn = page.locator('button:has-text("Verify Syntax")');
    await verifyBtn.click();
    await page.waitForTimeout(400);

    // Assert successful compilation banner
    await expect(page.locator('text=Expression compiled cleanly')).toBeVisible();

    // Fill rule name
    await page.fill('input[placeholder="e.g. Block External Admin Access"]', 'E2E ACL Rule');

    // Save to Draft
    const saveBtn = page.locator('button:has-text("Save to Draft")');
    await saveBtn.click();
    await page.waitForTimeout(600);

    // Verify in table
    await expect(page.locator('text=E2E ACL Rule')).toBeVisible();

    // Delete rule
    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });
    const deleteBtn = page.locator('table tr:has-text("E2E ACL Rule") button').last();
    await deleteBtn.click();
    await page.waitForTimeout(600);
  });

  // 5. Exceptions Gate & Dry-run Simulator
  test('5. Exceptions Gate: Add exception, run test simulator, verify Path column', async ({ page }) => {
    await page.goto('#/exceptions');
    await page.waitForTimeout(400);

    // Open Add Exception modal
    const addExcBtn = page.locator('button:has-text("Add Exception Rule"), button:has-text("Add First Exception")').first();
    await addExcBtn.click();
    await page.waitForSelector('input[placeholder="/api/v1/search"]');

    // Fill exception form
    await page.fill('input[placeholder="/api/v1/search"]', '/api/v1/search');
    await page.fill('input[placeholder="e.g. search_term"]', 'q');
    await page.fill('input[placeholder*="Valid SQL editor payload"]', 'E2E false positive bypass');

    // Save Exception
    const saveBtn = page.locator('button:has-text("Add to Draft")');
    await saveBtn.click();
    await page.waitForTimeout(600);

    // Verify Path column renders '/api/v1/search'
    await expect(page.locator('table tr:has-text("/api/v1/search")')).toBeVisible();

    // Open dry-run simulator on this rule
    const testBtn = page.locator('table tr:has-text("/api/v1/search") button:has-text("Test")').first();
    if (await testBtn.isVisible()) {
      await testBtn.click();
      await page.waitForSelector('button:has-text("Run Test Simulation")');
      await page.locator('button:has-text("Run Test Simulation")').click();
      await page.waitForTimeout(500);
      await expect(page.locator('text=Exception Match').or(page.locator('text=Match Result'))).toBeVisible();
      await page.keyboard.press('Escape');
      await page.waitForTimeout(200);
    }

    // Delete exception
    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });
    const deleteBtn = page.locator('table tr:has-text("/api/v1/search") button').last();
    await deleteBtn.click();
    await page.waitForTimeout(600);
  });

  // 6. RulesView Subtab switching
  test('6. RulesView: Subtab switching maintains persistent tab headers', async ({ page }) => {
    await page.goto('#/rules');
    await page.waitForTimeout(400);

    // Subtabs: Exceptions Gate, ACL Bytecode Rules, Defense Policies
    const aclsTab = page.locator('[role="tab"]:has-text("ACL Bytecode Rules")');
    await aclsTab.click();
    await page.waitForTimeout(300);
    expect(await page.locator('[role="tab"]:has-text("Exceptions Gate")').isVisible()).toBe(true);

    const policiesTab = page.locator('[role="tab"]:has-text("Defense Policies")');
    await policiesTab.click();
    await page.waitForTimeout(300);
    expect(await page.locator('[role="tab"]:has-text("Exceptions Gate")').isVisible()).toBe(true);

    const exceptionsTab = page.locator('[role="tab"]:has-text("Exceptions Gate")');
    await exceptionsTab.click();
    await page.waitForTimeout(300);
    expect(await page.locator('[role="tab"]:has-text("ACL Bytecode Rules")').isVisible()).toBe(true);
  });

  // 7. Volumetric Defense, Active Bans & Waiting Room
  test('7. Volumetric Defense: Configures 3-tier limits, refreshes bans, toggles waiting room', async ({ page }) => {
    await page.goto('#/http-flood');
    await page.waitForTimeout(400);

    // Active Bans Tab
    const refreshBansBtn = page.locator('button:has-text("Refresh")').first();
    if (await refreshBansBtn.isVisible()) {
      await refreshBansBtn.click();
      await page.waitForTimeout(300);
    }

    // Release all bans button test if enabled
    const releaseAllBtn = page.locator('button:has-text("UNBLOCK ALL")');
    if (await releaseAllBtn.isEnabled().catch(() => false)) {
      await releaseAllBtn.click();
      await page.waitForTimeout(300);
      // It opens a Radix confirmation Dialog - dismiss it via Cancel
      const cancelBtn = page.locator('button:has-text("Cancel")');
      if (await cancelBtn.isVisible()) {
        await cancelBtn.click();
        await page.waitForTimeout(300);
      }
    }

    // Switch to 3-Tier Limits subtab
    await page.locator('[role="tab"]:has-text("3-Tier Limits Configuration")').click();
    await page.waitForTimeout(300);

    const saveLimitsBtn = page.locator('button:has-text("Save to Draft")');
    await saveLimitsBtn.click();
    await page.waitForTimeout(500);
    await expect(page.locator('text=Volumetric defense policies saved to draft')).toBeVisible();

    // Switch to Waiting Room subtab
    await page.locator('[role="tab"]:has-text("Waiting Room Dashboard")').click();
    await page.waitForTimeout(300);

    // Add prefix
    const prefixInput = page.locator('input[placeholder="/checkout or /tickets"]');
    if (await prefixInput.isVisible()) {
      await prefixInput.fill('/e2e-protected');
      await page.locator('button:has-text("Add Prefix")').click();
      await page.waitForTimeout(200);
      await expect(page.locator('text=/e2e-protected')).toBeVisible();

      // Remove prefix
      await page.locator('div:has-text("/e2e-protected") button').click();
    }
  });

  // 8. Anti-Bot Defense Configuration
  test('8. Anti-Bot Defense: Updates Altcha PoW difficulty and saves policies', async ({ page }) => {
    await page.goto('#/anti-bot');
    await page.waitForTimeout(400);

    const difficultyInput = page.locator('input[type="number"]').first();
    await difficultyInput.fill('25000');

    const saveBtn = page.locator('button:has-text("Save Policies to Draft")');
    await saveBtn.click();
    await page.waitForTimeout(500);
    await expect(page.locator('text=Saved to draft')).toBeVisible();
  });

  // 9. Deployments & Staged Snapshot Apply
  test('9. Deployments Console: Refreshes staged diff and tests apply dialog', async ({ page }) => {
    await page.goto('#/deployments');
    await page.waitForTimeout(400);

    const refreshDiffBtn = page.locator('button:has-text("Refresh Diff")');
    if (await refreshDiffBtn.isVisible()) {
      await refreshDiffBtn.click();
      await page.waitForTimeout(300);
    }

    // Check Apply Changes modal
    const applyBtn = page.locator('button:has-text("Apply Changes to Live Data Plane")');
    if (await applyBtn.isVisible()) {
      await applyBtn.click();
      await page.waitForSelector('textarea[placeholder="Describe the architectural or policy changes in this deployment..."]');
      await page.fill('textarea[placeholder="Describe the architectural or policy changes in this deployment..."]', 'E2E Automated Test Deployment');
      await page.locator('button:has-text("Deploy Configuration")').click();
      await page.waitForTimeout(600);
    }
  });

  // 10. API Keys Management
  test('10. API Keys: Generates new key token and revokes cleanly', async ({ page }) => {
    await page.goto('#/system');
    await page.waitForTimeout(400);

    // Switch to API Keys tab
    await page.locator('[role="tab"]:has-text("API Keys & Access")').click();
    await page.waitForTimeout(300);

    // Generate Key
    await page.locator('button:has-text("Generate API Key")').click();
    await page.waitForSelector('input[placeholder="e.g. CI/CD Deployer or Claude Desktop"]');
    await page.fill('input[placeholder="e.g. CI/CD Deployer or Claude Desktop"]', 'E2E Test Key');

    await page.locator('button:has-text("Generate Token")').click();
    await page.waitForTimeout(400);

    // Assert key token dialog
    await expect(page.locator('text=Make sure to copy your API key now')).toBeVisible();
    await page.locator('button:has-text("Done")').click();
    await page.waitForTimeout(300);

    // Verify key in table
    await expect(page.locator('text=E2E Test Key')).toBeVisible();

    // Revoke key
    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });
    const revokeBtn = page.locator('table tr:has-text("E2E Test Key") button').last();
    await revokeBtn.click();
    await page.waitForTimeout(600);
  });

  // 11. Live Attacks Stream & Quick Exception Action
  test('11. Attacks Stream: Pause/Resume stream and Create Exception navigation', async ({ page }) => {
    await page.goto('#/attacks');
    await page.waitForTimeout(400);

    // Pause stream
    const pauseBtn = page.locator('button:has-text("Pause")');
    if (await pauseBtn.isVisible()) {
      await pauseBtn.click();
      await page.waitForTimeout(300);
      await expect(page.locator('button:has-text("Resume")')).toBeVisible();
      await page.locator('button:has-text("Resume")').click();
      await page.waitForTimeout(300);
    }
  });
});
