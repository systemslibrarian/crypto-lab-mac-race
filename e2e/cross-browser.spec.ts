import { expect, test } from '@playwright/test';
import { boot, expectNoHorizontalOverflow, NARROW } from './gate';

for (const narrow of [false, true]) {
  test(`core lesson works in dark theme at ${narrow ? 'phone' : 'desktop'} width`, async ({ page }) => {
    if (narrow) await page.setViewportSize(NARROW);
    await boot(page);
    await expect(page.locator('#theme-toggle')).toHaveCount(0);
    await expect(page.locator('#crc-key-leaked')).not.toBeChecked();

    await page.locator('#crc-accident').click();
    await expect(page.locator('#crc-verdict1')).toHaveText('✗ CORRUPTION CAUGHT');
    await page.locator('#crc-naive').click();
    await expect(page.locator('#crc-verdict2')).toHaveText('✗ REJECTED');
    await page.locator('#crc-repair').click();
    await expect(page.locator('#crc-verdict3')).toHaveText('⚠ CRC VALID — AND FORGED');
    await page.locator('#crc-target').fill('1234abcd');
    await expect(page.locator('#crc-verdict3')).toHaveText('⚠ CRC VALID — AND FORGED');
    await page.locator('#crc-force').click();
    await expect(page.locator('#crc-check3b [data-actual]')).toHaveText('1234abcd');
    await page.locator('#crc-hmac').click();
    await expect(page.locator('#crc-verdict4')).toHaveText('✗ REJECTED');
    await page.locator('#crc-key-leaked').check();
    await expect(page.locator('#crc-hmac-caption')).toContainText('With the leaked key');
    await page.locator('#crc-hmac').click();
    await expect(page.locator('#crc-verdict4')).toHaveText('⚠ TAG VALID — AND FORGED');
    await expectNoHorizontalOverflow(page, `dark ${narrow ? 'phone' : 'desktop'} lesson`);

    // Older copies of the lab stored a light preference. It cannot change the
    // dark-only page, and the opt-in leaked-key state still resets on reload.
    await page.evaluate(() => localStorage.setItem('theme', 'light'));
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('#crc-key-leaked')).not.toBeChecked();
  });
}
