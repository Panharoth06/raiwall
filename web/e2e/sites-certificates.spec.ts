import { test, expect, type Page } from '@playwright/test';

// Registration + certificate lifecycle across the three mandated viewports.
// Each viewport uses unique hostnames so parallel runs never collide.
const viewports = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
];

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

const unique = (prefix: string) => `${prefix}-${Date.now().toString(36)}`;
const host = (label: string) => `${label}.e2e.local`;

for (const vp of viewports) {
  test.describe(`sites + certificates ${vp.name} ${vp.width}x${vp.height}`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } });

    test(`registers an application, applies the draft, and removes it (${vp.name})`, async ({ page }) => {
      const label = unique(`site-${vp.name}`).toLowerCase();
      const siteName = `E2E ${vp.name} ${label}`;
      const domain = host(label);

      await login(page);
      await page.goto('#/sites');
      await page.getByRole('button', { name: 'Add Protected Site' }).first().click();

      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();

      const domainInput = dialog.getByPlaceholder('www.example.com, support *');
      await domainInput.fill(domain);
      await domainInput.press('Enter');

      // Drop the default "*" tag so the site only serves the test hostname.
      const removeButtons = dialog.locator('button[title="Remove domain"]');
      await removeButtons.first().click();

      await dialog.getByPlaceholder('Application Name').fill(siteName);
      await dialog.getByRole('button', { name: 'SUBMIT' }).click();

      await expect(dialog).toBeHidden();
      await expect(page.getByText(siteName)).toBeVisible();
      await expect(page.getByText(domain)).toBeVisible();

      const banner = page.locator('[data-testid="sites-pending-banner"]');
      await expect(banner).toBeVisible();
      await expect(banner).toContainText('staged change');

      await page.locator('[data-testid="sites-apply-now"]').click();
      await expect(banner).toBeHidden({ timeout: 15_000 });

      // Cleanup through the API so the stack stays usable across runs.
      const api = await page.request;
      const list = await api.get('/.raiwall/api/v1/sites', { headers: { Accept: 'application/json' } });
      expect(list.ok()).toBeTruthy();
      const sites = (await list.json()) as Array<{ id: string; name: string }>;
      const created = sites.find((s) => s.name === siteName);
      expect(created).toBeTruthy();
      await api.delete(`/.raiwall/api/v1/sites/${created!.id}`, {
        headers: { Accept: 'application/json' },
      });
      await api.post('/.raiwall/api/v1/config/apply', {
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        data: { author: 'admin', description: 'e2e cleanup' },
      });
    });

    test(`creates and deletes a managed certificate (${vp.name})`, async ({ page }) => {
      const label = unique(`cert-${vp.name}`).toLowerCase();
      const certName = `e2e ${vp.name} cert`;
      const domain = host(label);

      await login(page);
      await page.goto('#/settings');
      await page.getByTestId('tab-item').filter({ hasText: 'TLS Certificates' }).click();
      await page.getByRole('button', { name: 'Add Certificate' }).click();

      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();

      await dialog.getByPlaceholder('Primary wildcard').fill(certName);
      const domainInput = dialog.getByPlaceholder('app.example.com, *.example.com');
      await domainInput.fill(domain);
      await domainInput.press('Enter');

      await dialog.getByRole('button', { name: 'SUBMIT' }).click();
      await expect(dialog).toBeHidden();

      const row = page.getByRole('row').filter({ hasText: certName });
      await expect(row).toBeVisible();
      await expect(row).toContainText(domain);
      await expect(row).toContainText('Self-signed');

      await page.getByRole('button', { name: `Delete ${certName}` }).click();
      await page.getByRole('button', { name: 'Delete Certificate' }).click();

      await expect(page.getByRole('row').filter({ hasText: certName })).toHaveCount(0);
      await expect(page.getByText(`Deleted ${certName}`)).toBeVisible();
    });
  });
}
