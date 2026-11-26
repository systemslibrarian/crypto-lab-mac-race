import { expect, test } from '@playwright/test';
import { createHmac } from 'node:crypto';

test('the HMAC grid and verification verdict follow the displayed message', async ({ page }) => {
  await page.goto('./');
  const message = page.locator('#hmac-message');
  const tag = page.locator('#hmac-verify-tag');
  const verdict = page.locator('#hmac-verdict');
  const messageGrid = page.locator('#hmac-bitdiff-msg');
  const keyGrid = page.locator('#hmac-bitdiff-key');
  const expectedTag = (text: string) => createHmac('sha256', 'key').update(text).digest('hex');

  await page.locator('#hmac-key').fill('key');
  await message.fill('');
  await page.locator('#hmac-run').click();
  await expect(tag).toHaveValue(expectedTag(''));
  await expect(messageGrid).toContainText('no message bit');
  await expect(keyGrid).toContainText('116/256');
  await page.locator('#hmac-verify').click();
  await expect(verdict).toContainText('ACCEPTED');

  await message.fill('A');
  await expect(verdict).toHaveText('inputs changed — click Verify');
  await expect(messageGrid).toBeEmpty();
  await page.locator('#hmac-verify').click();
  await expect(verdict).toContainText('REJECTED');
  await page.locator('#hmac-run').click();
  await expect(tag).toHaveValue(expectedTag('A'));
  await expect(messageGrid).toContainText('121/256');
  await expect(keyGrid).toContainText('145/256');
});
