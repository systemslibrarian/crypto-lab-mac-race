import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Every exhibit's computed output and verdict is scanned in both themes at
 * desktop and phone width. See `gate.ts` for why nothing is injected into the
 * page, why each scan asserts its content first, and why `violations` is not
 * the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);

    // The third ratchet rule — a baselined finding that no longer appears must
    // be deleted, so the list can only shrink. `expectBaselineNotStale` was
    // exported from `gate.ts` and imported by nothing, so it had never run.
    //
    // It belongs in exactly this one configuration, which was measured rather
    // than assumed. `nonTextSeen` is a single flat set with no theme or width
    // dimension, so the check is only sound where the drive reaches EVERY
    // baselined selector, and only this configuration does:
    //   - light theme produces no non-text findings at all (every control
    //     boundary clears 3:1 against the light surfaces), so calling it there
    //     reports all 18 dark-theme entries as stale on every run;
    //   - dark at desktop misses `button#tour-start`. `.tour` is painted with a
    //     140deg `linear-gradient` and `.tour-head` is `space-between` with
    //     `flex-wrap`, so the button sits at the right end of that gradient on
    //     desktop and wraps to the left end at 380px. Different backdrop,
    //     different ratio: 2.7:1 here, above 3:1 there. Confirmed through the
    //     gate's own capture path, which emits the finding at 380px and nothing
    //     at desktop.
    // The baseline is therefore a description of the dark drive at phone width,
    // and this is the only place the rule can hold.
    if (theme === 'dark') expectBaselineNotStale();
  });
}
