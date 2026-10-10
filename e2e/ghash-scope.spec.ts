import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`raw GHASH and real GCM scopes stay distinct at ${width}px`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    const scope = page.locator('#ghash-model-scope');
    await expect(scope).toBeVisible();
    await expect(scope).toContainText('raw single-block field-product toy');
    await expect(scope).toContainText('length block');
    await expect(scope).toContainText('nonce-derived mask');
    await expect(scope).toContainText('H²');
    await expect(scope).toContainText('even with different nonces');
    await expect(page.locator('#p4')).not.toContainText('same operation a real GCM endpoint runs');
    await expect(page.locator('#ghash-attack')).toHaveText('Run raw-field toy →');
    // Normal GHASH computation includes the length block; no new attack run.
    await page.locator('#ghash-run').click();
    await expect(page.locator('#ghash-output')).toContainText('GHASH output:');
    await expect(page.locator('#ghash-output')).toContainText('length block included; not an AES-GCM tag');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
