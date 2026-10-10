import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`Poly1305 disclosure and ordinary tag computation at ${width}px`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    const disclosure = page.locator('#poly-reuse-scope');
    await expect(disclosure).toBeVisible();
    await expect(disclosure).toContainText('simple classroom brute-force search');
    await expect(disclosure).toContainText('small number of tag-truncation carry candidates');
    await expect(disclosure).toContainText('additional observation may be needed');
    await expect(disclosure).not.toContainText('not tractable');
    await expect(page.locator('#p3')).toContainText('unique one-time key per message');
    // Ordinary authentication path only: no new recovery or forgery procedure.
    await page.locator('#poly-run').click();
    await expect(page.locator('#poly-output')).toContainText('Poly1305 tag:');
    await expect(page.locator('#poly-output')).toContainText('Reusing it breaks authenticity');
    const output = await page.locator('#poly-output').innerText();
    expect(output).toMatch(/Poly1305 tag: [0-9a-f]{32}/);
    expect(output).toMatch(/One-time key: [0-9a-f]{64}/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
