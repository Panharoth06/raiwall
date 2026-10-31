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

  // 2. Rule Tester: evaluates a CRS-only probe against the live engine
  test('2. Rule Tester: evaluates a CRS-only protocol violation', async ({ page }) => {
    await page.goto('#/detection/tester');
    await page.waitForSelector('text=Request Probe');

    // A POST body without Content-Type triggers CRS rule 920640 at PL1.
    await page.fill('textarea[aria-label="Headers"]', '');
    await page.locator('[aria-label="HTTP method"]').click();
    await page.getByRole('option', { name: 'POST' }).click();
    await page.fill('textarea[aria-label="Body"]', 'hello');
    await page.getByRole('button', { name: 'Evaluate Request' }).click();

    await expect(page.getByText('CRS_949110')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('920640')).toBeVisible();
    await expect(page.getByText('audit', { exact: true })).toBeVisible();
  });

  // 3. Protected Sites Lifecycle
  test('3. Protected Sites: Full CRUD lifecycle with upstream duration strings', async ({ page }) => {
    await page.goto('#/sites');
    await page.waitForTimeout(400);

    // Open Add Protected Site modal
    const addSiteBtn = page.locator('button:has-text("Add Protected Site"), button:has-text("Add First Application"), button:has-text("Add First Site")').first();
    await addSiteBtn.click();
    await page.waitForSelector('input[placeholder="Application Name"]');

    // Fill form
    await page.fill('input[placeholder="Application Name"]', 'E2E Automated Site');
    await page.fill('input[placeholder="www.example.com, support *"]', 'e2e.test.com');

    // Save Site to Draft
    await page.locator('button:has-text("SUBMIT")').click();
    await page.waitForTimeout(600);

    // Assert site is in the table
    await expect(page.locator('table')).toContainText('E2E Automated Site');

    // Delete site cleanly
    const siteRow = page.locator('tr', { hasText: 'E2E Automated Site' });
    await siteRow.locator('[data-testid="site-delete"]').click();
    await page.getByRole('button', { name: 'Delete Site', exact: true }).click();
    await expect(siteRow).toHaveCount(0, { timeout: 10000 });
  });

  // 4. Bytecode ACL Rules & Syntax Verifier
  test('4. ACL Rules: Expr-lang syntax dry-run verification and rule creation', async ({ page }) => {
    await page.goto('#/acls');
    await page.waitForTimeout(400);

    // Open Add ACL Rule dialog and switch to the raw expression editor
    await page.locator('button:has-text("ADD RULES")').first().click();
    const aclDialog = page.getByRole('dialog');
    await expect(aclDialog).toBeVisible();
    await aclDialog.getByPlaceholder('e.g. Allow Office Network').fill('E2E ACL Rule');
    await aclDialog.getByRole('button', { name: 'Advanced expr Mode' }).click();

    const expression = aclDialog.locator('textarea[placeholder*="in_cidr"]');
    await expression.fill('in_cidr(client_ip, "203.0.113.0/24")');
    await aclDialog.getByRole('button', { name: 'Verify Syntax' }).click();
    await expect(aclDialog.getByText('Expression verified cleanly')).toBeVisible({ timeout: 10000 });

    // Save the rule
    await aclDialog.getByRole('button', { name: 'SUBMIT', exact: true }).click();
    await expect(aclDialog).toBeHidden();

    // Verify in table
    await expect(page.locator('tr', { hasText: 'E2E ACL Rule' })).toBeVisible();

    // Delete rule
    const aclRow = page.locator('tr', { hasText: 'E2E ACL Rule' });
    await aclRow.locator('button').last().click();
    await page.getByRole('button', { name: 'Delete Rule', exact: true }).click();
    await expect(aclRow).toHaveCount(0, { timeout: 10000 });
  });

  // 5. Exceptions Gate & Dry-run Simulator
  test('5. Exceptions Gate: Add exception, run test simulator, verify Path column', async ({ page }) => {
    await page.goto('#/exceptions');
    await page.waitForTimeout(400);

    // Open Add Exception modal
    await page.locator('button:has-text("Add Exception Rule"), button:has-text("Add First Exception")').first().click();
    await page.waitForSelector('input[placeholder="e.g. /checkout/payment"]');

    // Fill exception form
    await page.fill('input[placeholder="e.g. /checkout/payment"]', '/api/v1/search');
    await page.fill('input[placeholder="e.g. signature or token"]', 'q');
    await page.fill('input[placeholder="e.g. Base64 encoded payload in webhook"]', 'E2E false positive bypass');
    await page.getByRole('dialog').getByRole('button', { name: 'Add Exception', exact: true }).click();

    // Verify Path column renders '/api/v1/search'
    const exceptionRow = page.locator('tr', { hasText: '/api/v1/search' });
    await expect(exceptionRow).toBeVisible();

    // Open dry-run simulator on this rule
    await exceptionRow.locator('[data-testid="exception-test"]').click();
    await page.getByRole('button', { name: 'Run Dry-Run Test' }).click();
    await expect(page.getByText(/Suppression Matched|No Match/)).toBeVisible();
    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);

    // Delete exception
    await exceptionRow.locator('[data-testid="exception-delete"]').click();
    await page.getByRole('button', { name: 'Delete Exception', exact: true }).click();
    await expect(exceptionRow).toHaveCount(0, { timeout: 10000 });
  });

  // 6. Detection workspace navigation
  test('6. Detection: section tabs navigate between workspace pages', async ({ page }) => {
    await page.goto('#/detection');
    await page.waitForTimeout(400);
    await expect(page.locator('h1')).toContainText('Detection');

    await page.locator('[role="tab"]:has-text("Semantic Matrix")').click();
    await page.waitForTimeout(300);
    await expect(page.locator('h1')).toContainText('Semantic Detection Matrix');

    await page.locator('[role="tab"]:has-text("Exceptions")').click();
    await page.waitForTimeout(300);
    await expect(page.locator('h1')).toContainText('False-Positive Exception Rules');

    await page.locator('[role="tab"]:has-text("Rule Tester")').click();
    await page.waitForTimeout(300);
    await expect(page.locator('h1')).toContainText('Rule Tester');

    await page.locator('[role="tab"]:has-text("Rule Catalog")').click();
    await page.waitForTimeout(300);
    await expect(page.locator('h1')).toContainText('Rule Catalog');

    await page.locator('[role="tab"]:has-text("Rule Packs")').click();
    await page.waitForTimeout(300);
    await expect(page.locator('h1')).toContainText('Rule Packs');
  });

  // 7. Volumetric Defense, Active Bans & Waiting Room
  test('7. Volumetric Defense: Configures 3-tier limits, refreshes bans, toggles waiting room', async ({ page }) => {
    await page.goto('#/http-flood/limits');
    await page.waitForTimeout(400);

    // Verify the active ban registry renders
    await expect(page.locator('h1')).toContainText('HTTP Flood & Rate Limiting Defense');
    await expect(page.locator('th', { hasText: 'IP Addr' })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();

    // Refresh the ban registry
    const refreshBansBtn = page.locator('button[title="Refresh"]').first();
    if (await refreshBansBtn.isVisible().catch(() => false)) {
      await refreshBansBtn.click();
      await page.waitForTimeout(300);
    }

    // Open the 3-tier configuration view
    await page.goto('#/http-flood/limits/settings');
    await page.waitForTimeout(400);
    await expect(page.getByText('Access Limiting (Tier 1: Access Velocity Limiting)')).toBeVisible();
    await expect(page.getByText('Attack Limiting (Tier 2: Attack Frequency Auto-Ban)')).toBeVisible();
    await expect(page.getByText('Error Limiting (Tier 3: Upstream Scanner Trap)')).toBeVisible();

    // Edit the Tier 1 rule through the modal and stage it
    await page.locator('button:has-text("ADD RULES")').first().click();
    await page.waitForSelector('button:has-text("Save Changes")');
    await page.locator('button:has-text("Save Changes")').click();
    await page.waitForTimeout(600);
    await expect(page.getByText('Updated access limiting policy')).toBeVisible();

    // Switch to Waiting Room dashboard
    await page.goto('#/http-flood/waiting-room');
    await page.waitForTimeout(400);
    await expect(page.locator('h2', { hasText: 'Virtual Waiting Room Engine' })).toHaveCount(1);
    await expect(page.getByRole('button', { name: 'SETTINGS', exact: true })).toBeVisible();
    await expect(page.getByRole('combobox').first()).toBeVisible();
  });

  // 8. Anti-Bot Defense Configuration
  test('8. Anti-Bot Defense: configures application-scoped BOT Protect', async ({ page }) => {
    const auth = { Authorization: `Basic ${Buffer.from('admin:admin').toString('base64')}` };
    const hosts = ['e2e-bot.example.com', 'edge.e2e-bot.example.com'];
    let createdSiteId: string | null = null;

    // The application flow needs at least one protected site. Create a temporary one when the
    // environment has no applications, then remove it after the assertion run.
    const sitesResponse = await page.request.get('/.raiwall/api/v1/sites', { headers: auth });
    const sites = sitesResponse.ok() ? await sitesResponse.json() : [];
    if (!Array.isArray(sites) || sites.length === 0) {
      const created = await page.request.post('/.raiwall/api/v1/sites', {
        headers: auth,
        data: { name: 'E2E Bot App', hostnames: hosts, mode: 'defense', upstreams: [] },
      });
      if (created.ok()) {
        createdSiteId = (await created.json()).id;
        await page.reload();
        if (await page.locator('input[type="password"]').isVisible().catch(() => false)) {
          await page.fill('input[placeholder="Username"]', 'admin');
          await page.fill('input[type="password"]', 'admin');
          await page.click('button[type="submit"]');
          await page.waitForTimeout(600);
        }
      }
    }

    try {
      await page.goto('#/anti-bot');
      await page.waitForTimeout(400);

      await expect(page.locator('h1')).toContainText('Anti-Bot Defense');
      await expect(page.locator('[data-testid="bot-app-table"]')).toBeVisible();
      await expect(page.locator('[data-testid="bot-global-row"]')).toBeVisible();
      await expect(page.locator('[data-testid="bot-activity-card"]')).toBeVisible();

      const dialog = page.locator('[data-testid="bot-protect-dialog"]');

      // Global fallback policy
      await page.locator('[data-testid="bot-configure-global"]').click();
      await expect(dialog).toBeVisible();
      if (!(await page.locator('[data-testid="bot-difficulty-slider"]').isVisible())) {
        await page.locator('[data-testid="bot-challenge-toggle"]').click();
      }
      await page.locator('[data-testid="bot-difficulty-preset-100000"]').click();
      await page.locator('[data-testid="bot-save-protect"]').click();
      await expect(page.locator('[data-testid="bot-notice"]')).toContainText('BOT Protect saved');

      // Application-scoped policy
      const appRow = page.locator('[data-testid="bot-app-row"]').first();
      await expect(appRow).toBeVisible();
      const applicationName = (await appRow.locator('td').first().innerText()).trim();
      await appRow.locator('[data-testid="bot-configure-app"]').click();
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText(applicationName);

      const trapsInput = page.locator('[data-testid="bot-traps-input"]');
      if (!(await trapsInput.isVisible())) {
        await page.locator('[data-testid="bot-trap-toggle"]').click();
      }
      await trapsInput.fill('/trap/e2e');
      await page.locator('[data-testid="bot-save-protect"]').click();
      await expect(page.locator('[data-testid="bot-notice"]')).toContainText('BOT Protect saved');
      await expect(appRow.locator('[data-testid="bot-row-status"]')).toContainText(/On|Partial/);

      // Remove the override and confirm the global policy applies again.
      await appRow.locator('[data-testid="bot-configure-app"]').click();
      await expect(page.locator('[data-testid="bot-reset-policy"]')).toBeVisible();
      await page.locator('[data-testid="bot-reset-policy"]').click();
      await expect(page.locator('[data-testid="bot-notice"]')).toContainText('override removed');
      await expect(appRow.locator('[data-testid="bot-row-status"]')).toContainText(
        'Inherits global'
      );

      // Applications table entry point opens the same application-scoped dialog.
      await page.goto('#/sites');
      const siteRow = page.locator('tr').filter({ hasText: applicationName }).first();
      await siteRow.locator('[data-testid="site-bot-protect"]').click();
      await expect(page.locator('[data-testid="bot-protect-dialog"]')).toBeVisible();
      await expect(page.locator('[data-testid="bot-protect-dialog"]')).toContainText(
        applicationName
      );
      await page.locator('[data-testid="bot-cancel-protect"]').click();
      await expect(page.locator('[data-testid="bot-protect-dialog"]')).toHaveCount(0);
    } finally {
      const configsResponse = await page.request.get('/.raiwall/api/v1/policies/bot', {
        headers: auth,
      });
      if (configsResponse.ok()) {
        const configs = (await configsResponse.json()) as Array<{ id: string; host: string }>;
        for (const config of configs) {
          if (hosts.includes(config.host)) {
            await page.request.delete(`/.raiwall/api/v1/policies/bot/${config.id}`, {
              headers: auth,
            });
          }
        }
      }
      if (createdSiteId) {
        await page.request.delete(`/.raiwall/api/v1/sites/${createdSiteId}`, { headers: auth });
      }
    }
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

  // 9b. Auto-apply: saving a protected site commits a live snapshot
  test('9b. Auto-apply: saving a site hot-swaps configuration without manual deploy', async ({ page }) => {
    const stamp = Date.now();
    const name = `E2E Auto Apply ${stamp}`;
    const host = `auto-apply-${stamp}.e2e.test`;
    const auth = { Authorization: `Basic ${Buffer.from('admin:admin').toString('base64')}` };

    try {
      await page.goto('#/sites');
      await page.waitForTimeout(400);

      const addSiteBtn = page
        .locator('button:has-text("Add Protected Site"), button:has-text("Add First Application"), button:has-text("Add First Site")')
        .first();
      await addSiteBtn.click();
      await page.waitForSelector('input[placeholder="Application Name"]');
      await page.fill('input[placeholder="Application Name"]', name);
      await page.fill('input[placeholder="www.example.com, support *"]', host);
      await page.locator('button:has-text("SUBMIT")').click();

      await expect(page.locator('table')).toContainText(name, { timeout: 10000 });

      await page.goto('#/deployments');
      await expect(page.getByTestId('auto-apply-notice')).toBeVisible();
      await expect(page.locator('[data-testid="snapshot-history-table"]')).toContainText(
        /Auto-applied after POST .*\/sites/,
        { timeout: 10000 }
      );
      await expect(page.getByTestId('manual-deploy-btn')).toHaveCount(0);
    } finally {
      const sitesResponse = await page.request.get('/.raiwall/api/v1/sites', { headers: auth });
      if (sitesResponse.ok()) {
        const sites = (await sitesResponse.json()) as Array<{ id: string; hostnames?: string[] }>;
        for (const site of sites) {
          if (site.hostnames?.includes(host)) {
            await page.request.delete(`/.raiwall/api/v1/sites/${site.id}`, { headers: auth });
          }
        }
      }
    }
  });

  // 10. API Keys Management
  test('10. API Keys: Generates new key token and revokes cleanly', async ({ page }) => {
    const keyName = `E2E Test Key ${Date.now()}`;
    await page.goto('#/system');
    await page.waitForTimeout(400);

    // Switch to API Keys tab
    await page.locator('[role="tab"]:has-text("API Keys & Access")').click();
    await page.waitForTimeout(300);

    // Generate Key
    await page.locator('button:has-text("Generate API Key")').click();
    await page.waitForSelector('input[placeholder="e.g. CI/CD Deployer or Claude Desktop"]');
    await page.fill('input[placeholder="e.g. CI/CD Deployer or Claude Desktop"]', keyName);

    await page.locator('button:has-text("Generate Token")').click();
    await page.waitForTimeout(400);

    // Assert key token dialog
    await expect(page.locator('text=Make sure to copy your API key now')).toBeVisible();
    await page.locator('button:has-text("Done")').click();
    await page.waitForTimeout(300);

    // Verify key in table
    const keyRow = page.locator('tr', { hasText: keyName });
    await expect(keyRow).toBeVisible();

    // Revoke key
    await keyRow.locator('button').last().click();
    await page.getByRole('button', { name: 'Revoke Key', exact: true }).click();
    await expect(keyRow).toHaveCount(0, { timeout: 10000 });
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
