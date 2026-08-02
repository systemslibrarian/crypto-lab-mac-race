import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT vectors;
 * this gates them on accessibility the same way. Scans the full page with
 * every <details> expanded and every collapsible/hidden region revealed, in
 * both themes (dark default + light).
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealEverything(page: Page): Promise<void> {
  // Neutralize animations/transitions/opacity so nothing is mid-fade when axe
  // measures contrast.
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}
      .step-line,[hidden]{opacity:1!important}`,
  });

  await page.evaluate(() => {
    // Expand every native <details>.
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal every element the app hides via the [hidden] attribute
    // (tour controls, stepper lines, tour progress).
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealEverything(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await scan(page);
});

test('length-extension verdict reports the forged guess and keeps the secret hidden', async ({ page }) => {
  await page.goto('.');
  await page.locator('#le-capture').click();
  await page.locator('#le-guess').fill('8');
  await page.locator('#le-forge').click();
  await expect(page.locator('#le-forge-output')).toContainText('Guessed secret length: 8');

  // Moving the slider after forging must not rewrite the history of the
  // attempt that is about to be verified.
  await page.locator('#le-guess').fill('9');
  await page.locator('#le-verify-raw').click();
  await expect(page.locator('#le-summary')).toContainText('guess 8');
  await expect(page.locator('#le-summary')).not.toContainText('actual length');
});
