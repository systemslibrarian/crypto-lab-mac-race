import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate for the dark-only lab. It scans every exhibit's
 * computed output and verdict at desktop and phone width, including the CRC
 * burst and both HMAC key branches.
 */
test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  test.setTimeout(900_000);
  await boot(page);
  await driveAllStates(page, 'dark');
});

test('no WCAG A/AA violations in dark theme at 380px', async ({ page }) => {
  test.setTimeout(900_000);
  await page.setViewportSize(NARROW);
  await boot(page);
  await driveAllStates(page, 'dark @380px');

  // The non-text baseline was captured at this width. The tour controls wrap
  // differently here, so this is the drive that reaches every baselined state.
  expectBaselineNotStale();
});
