import { expect, test as base, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate on the claims this lab makes on screen.
 *
 * The a11y suite proves the page is reachable and the Vitest suite proves the
 * primitives match their KAT vectors; neither proves that the *page* reaches
 * the states it advertises. This suite drives the real panels and re-derives
 * every verdict from what the page itself printed: the HMAC tag against its own
 * step list, the GHASH deltas against the ciphertexts and tags beside them, the
 * timing summary against the rows above it, and the length-extension verdicts
 * against a full sweep of the attacker's search space.
 */

/** Any uncaught page exception (or console error) fails the test that caused it. */
const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
      });
      await use(errors);
      expect(errors, 'uncaught page errors').toEqual([]);
    },
    { auto: true },
  ],
});

async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#p1-title')).toHaveText('HMAC');
}

/** Whitespace-preserving panel text (the <pre> panels are line-oriented). */
async function text(page: Page, selector: string): Promise<string> {
  return page.locator(selector).innerText();
}

/** Whitespace-normalised panel text, for prose panels. */
async function flat(page: Page, selector: string): Promise<string> {
  return (await page.locator(selector).innerText()).replace(/\s+/g, ' ').trim();
}

function grab(source: string, pattern: RegExp): RegExpMatchArray {
  const match = source.match(pattern);
  expect(match, `expected ${pattern} in: ${source}`).not.toBeNull();
  return match as RegExpMatchArray;
}

const hexToBytes = (hex: string): number[] =>
  (hex.match(/../g) ?? []).map((pair) => Number.parseInt(pair, 16));

const xorHex = (a: string, b: string): string => {
  const x = hexToBytes(a);
  const y = hexToBytes(b);
  expect(x).toHaveLength(y.length);
  return x.map((v, i) => (v ^ y[i]!).toString(16).padStart(2, '0')).join('');
};

const popcount = (hex: string): number =>
  hexToBytes(hex).reduce((total, byte) => {
    let bits = 0;
    for (let i = 0; i < 8; i += 1) bits += (byte >> i) & 1;
    return total + bits;
  }, 0);

/** Assert a verdict chip shows the expected word *and* the matching state class. */
async function expectVerdict(chip: Locator, expected: 'ACCEPTED' | 'REJECTED'): Promise<void> {
  await expect(chip).toHaveText(expected);
  await expect(chip).toHaveClass(
    new RegExp(expected === 'ACCEPTED' ? 'verdict-accept' : 'verdict-reject'),
  );
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

test('HMAC: the tag is the last step of its own derivation, and the server accepts only that tag', async ({
  page,
}) => {
  await open(page);

  await page.locator('#hmac-run').click();
  await expect(page.locator('#hmac-output')).toContainText('HMAC-SHA-256 tag');

  const steps = await text(page, '#hmac-output');
  const inner = grab(steps, /Step 4 — inner = SHA-256\(ipad ∥ message\):\s+([0-9a-f]{64})/)[1];
  const outer = grab(steps, /Step 5 — outer = SHA-256\(opad ∥ inner\) = TAG:\s+([0-9a-f]{64})/)[1];
  const tag256 = grab(steps, /HMAC-SHA-256 tag:\s+([0-9a-f]{64})/)[1];
  const tag512 = grab(steps, /HMAC-SHA-512 tag:\s+([0-9a-f]{128})/)[1];

  // The headline tag is the outer hash the step list just derived — not an
  // independently computed value that could drift from the explanation.
  expect(tag256).toBe(outer);
  expect(outer).not.toBe(inner);
  expect(tag512).not.toBe(tag256);

  // The verifier is pre-filled with that tag; the server must accept it.
  await expect(page.locator('#hmac-verify-tag')).toHaveValue(tag256);
  await page.locator('#hmac-verify').click();
  await expectVerdict(page.locator('#hmac-verdict'), 'ACCEPTED');

  // Tamper the tag by one nibble: rejected.
  const flipped = (tag256[0] === '0' ? '1' : '0') + tag256.slice(1);
  await page.locator('#hmac-verify-tag').fill(flipped);
  await page.locator('#hmac-verify').click();
  await expectVerdict(page.locator('#hmac-verdict'), 'REJECTED');

  // Tamper the message instead, leaving the genuine tag: also rejected. This is
  // the intro card's whole claim — change a byte and the tag no longer matches.
  await page.locator('#hmac-verify-tag').fill(tag256);
  await page.locator('#hmac-message').fill('transfer=4200&to=mallory');
  await page.locator('#hmac-verify').click();
  await expectVerdict(page.locator('#hmac-verdict'), 'REJECTED');
});

test('HMAC avalanche: each bit-diff grid counts the cells it drew, and ~half the tag bits flip', async ({
  page,
}) => {
  await open(page);
  await page.locator('#hmac-run').click();
  await expect(page.locator('#hmac-output')).toContainText('HMAC-SHA-256 tag');

  for (const block of ['#hmac-bitdiff-msg', '#hmac-bitdiff-key']) {
    const label = await flat(page, `${block} .bitdiff-label`);
    const parsed = grab(label, /— (\d+)\/(\d+) bits flipped \((\d+\.\d)%\)/);
    const flipped = Number(parsed[1]);
    const total = Number(parsed[2]);
    const pct = Number(parsed[3]);

    // The label must count the grid it is labelling.
    expect(await page.locator(`${block} .bitdiff-cell`).count()).toBe(total);
    expect(await page.locator(`${block} .bitdiff-flip`).count()).toBe(flipped);
    expect(total).toBe(256);
    expect(pct).toBeCloseTo((flipped / total) * 100, 1);

    // The stated security property: a one-bit input change flips about half the
    // output bits. 30–70% is ~6 sd of the binomial for 256 bits.
    expect(pct, `${block} avalanche`).toBeGreaterThan(30);
    expect(pct, `${block} avalanche`).toBeLessThan(70);
  }
});

// ---------------------------------------------------------------------------
// CMAC
// ---------------------------------------------------------------------------

test('CMAC: the 10* padding and K1/K2 steps feed the tag the server accepts', async ({ page }) => {
  await open(page);

  await page.locator('#cmac-run').click();
  await expect(page.locator('#cmac-output')).toContainText('Final encrypt');

  const steps = await text(page, '#cmac-output');
  const k1 = grab(steps, /K1 \(after << 1 \+ Rb\):\s+([0-9a-f]{32})/)[1];
  const k2 = grab(steps, /K2:\s+([0-9a-f]{32})/)[1];
  const padded = grab(steps, /Padded last block \(10\* if needed\):\s+([0-9a-f]{32})/)[1];
  const finalXor = grab(steps, /Final block XOR with K1\/K2:\s+([0-9a-f]{32})/)[1];
  const tag = grab(steps, /Final encrypt = TAG:\s+([0-9a-f]{32})/)[1];

  expect(k1).not.toBe(k2);

  // "audit-log-entry" is 15 bytes, so SP 800-38B applies 10* padding and the
  // final block is XORed with K2 — both visible in the steps.
  const messageHex = Buffer.from('audit-log-entry', 'utf8').toString('hex');
  expect(padded).toBe(`${messageHex}80`);
  expect(finalXor).toBe(xorHex(padded, k2));

  await expect(page.locator('#cmac-verify-tag')).toHaveValue(tag);
  await page.locator('#cmac-verify').click();
  await expectVerdict(page.locator('#cmac-verdict'), 'ACCEPTED');

  const flipped = (tag[0] === '0' ? '1' : '0') + tag.slice(1);
  await page.locator('#cmac-verify-tag').fill(flipped);
  await page.locator('#cmac-verify').click();
  await expectVerdict(page.locator('#cmac-verdict'), 'REJECTED');
});

// ---------------------------------------------------------------------------
// Poly1305
// ---------------------------------------------------------------------------

test('Poly1305: reusing the one-time key recovers r and the server accepts the forged tag', async ({
  page,
}) => {
  await open(page);

  // Failure path first: nothing to submit before the attack has run.
  await page.locator('#poly-verify').click();
  await expect(page.locator('#poly-verdict')).toHaveText('run the attack first');
  await expect(page.locator('#poly-verdict')).toHaveClass(/verdict-idle/);

  await page.locator('#poly-run').click();
  const tagLine = grab(await text(page, '#poly-output'), /Poly1305 tag: ([0-9a-f]{32})/);
  grab(await text(page, '#poly-output'), /One-time key: ([0-9a-f]{64})/);
  expect(tagLine[1]).toHaveLength(32);

  await page.locator('#poly-attack').click();
  await expect(page.locator('#poly-attack-output')).toContainText('Solved r');

  const attack = await text(page, '#poly-attack-output');
  const bits = Number(grab(attack, /r constrained to (\d+) bits/)[1]);
  const r = grab(attack, /Solved r = 0x([0-9a-f]+) \(searched 2\^(\d+) candidates\)/);
  const tag1 = grab(attack, /Invoice=1000USD\s+→\s+tag ([0-9a-f]{32})/)[1];
  const tag2 = grab(attack, /Invoice=9000USD\s+→\s+tag ([0-9a-f]{32})/)[1];
  const forged = grab(attack, /Forged Invoice=9999USD\s+→\s+tag ([0-9a-f]{32})/)[1];

  // The disclosed teaching simplification and the search actually performed
  // must be the same number.
  expect(Number(r[2])).toBe(bits);
  expect(bits).toBe(16);
  expect(Number.parseInt(r[1], 16)).toBeLessThan(2 ** bits);

  // Two distinct messages under one key give two distinct tags, and the forgery
  // is a third, new tag.
  expect(tag1).not.toBe(tag2);
  expect(forged).not.toBe(tag1);
  expect(forged).not.toBe(tag2);

  // The panel's headline claim, then the server's independent confirmation.
  expect(attack).toContain('Forgery matches the true tag under the real key: VALID.');
  await page.locator('#poly-verify').click();
  await expectVerdict(page.locator('#poly-verdict'), 'ACCEPTED');
});

// ---------------------------------------------------------------------------
// GHASH
// ---------------------------------------------------------------------------

test('GHASH: nonce reuse recovers H, the printed deltas really are the XORs, and the forgery verifies', async ({
  page,
}) => {
  await open(page);

  await page.locator('#ghash-verify').click();
  await expect(page.locator('#ghash-verdict')).toHaveText('run the attack first');

  // The compute panel: the last per-block state IS the reported GHASH output.
  await page.locator('#ghash-run').click();
  await expect(page.locator('#ghash-output')).toContainText('GHASH output');
  const compute = await text(page, '#ghash-output');
  const y = grab(compute, /GHASH output:\s+([0-9a-f]{32})/)[1];
  const chain = grab(compute, /Per-block:\s+(.+)/)[1].trim().split(' → ');
  expect(chain.at(-1)).toBe(y);
  grab(compute, /H = E_K\(0\^128\): ([0-9a-f]{32})/);

  await page.locator('#ghash-attack').click();
  await expect(page.locator('#ghash-attack-output')).toContainText('Recovered H');

  const attack = await text(page, '#ghash-attack-output');
  const c1 = grab(attack, /C1 ([0-9a-f]{32})\s+→\s+T1 ([0-9a-f]{32})/);
  const c2 = grab(attack, /C2 ([0-9a-f]{32})\s+→\s+T2 ([0-9a-f]{32})/);
  const deltaC = grab(attack, /Δ ciphertext: ([0-9a-f]{32})/)[1];
  const deltaT = grab(attack, /Δ tag:\s+([0-9a-f]{32})/)[1];
  const recoveredH = grab(attack, /Recovered H = ΔT · \(ΔC\)⁻¹ = ([0-9a-f]{32})/)[1];

  // The algebra the panel draws must be the algebra of the numbers it printed.
  expect(deltaC).toBe(xorHex(c1[1], c2[1]));
  expect(deltaT).toBe(xorHex(c1[2], c2[2]));

  // The attack is graded by the holder of the true H, not by itself.
  expect(attack).toContain('Recovered H equals the true hidden H: YES');
  expect(attack).toContain('Server (holds true H) accepts forgery: VALID.');
  expect(recoveredH).toHaveLength(32);

  // The bit-row picture must show the same bits as the hex above it: six rows
  // (T1, T2, T1⊕T2, C1, C2, C1⊕C2), each with popcount(hex) cells lit.
  const rows = page.locator('#ghash-linviz-rows .bitrow');
  await expect(rows).toHaveCount(6);
  const expectedHex = [c1[2], c2[2], deltaT, c1[1], c2[1], deltaC];
  for (let i = 0; i < expectedHex.length; i += 1) {
    await expect(rows.nth(i).locator('.bitrow-cell')).toHaveCount(128);
    await expect(
      rows.nth(i).locator('.bitrow-on'),
      `row ${i} must light popcount(${expectedHex[i]}) bits`,
    ).toHaveCount(popcount(expectedHex[i]!));
  }

  await page.locator('#ghash-verify').click();
  await expectVerdict(page.locator('#ghash-verdict'), 'ACCEPTED');
});

// ---------------------------------------------------------------------------
// Length extension
// ---------------------------------------------------------------------------

/** Forge with a guessed secret length and submit to both servers. */
async function forgeAndSubmit(page: Page, guess: number): Promise<{ raw: string; hmac: string }> {
  await page.locator('#le-guess').fill(String(guess));
  await expect(page.locator('#le-guess-value')).toHaveText(String(guess));
  await page.locator('#le-forge').click();
  await expect(page.locator('#le-forge-output')).toContainText(`Guessed secret length: ${guess}`);
  await page.locator('#le-verify-raw').click();
  await expect(page.locator('#le-verdict-raw')).not.toHaveText('forged — submit it');
  const raw = await page.locator('#le-verdict-raw').innerText();
  await page.locator('#le-verify-hmac').click();
  await expect(page.locator('#le-verdict-hmac')).not.toHaveText('forged — submit it');
  const hmac = await page.locator('#le-verdict-hmac').innerText();
  return { raw, hmac };
}

test('length extension: exactly one secret-length guess forges a tag the broken server accepts, and HMAC rejects them all', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await open(page);

  await page.locator('#le-capture').click();
  await expect(page.locator('#le-raw-tag')).toHaveText(/^[0-9a-f]{64}$/);
  const rawTag = await page.locator('#le-raw-tag').innerText();
  const hmacTag = await page.locator('#le-hmac-tag').innerText();
  expect(hmacTag).toMatch(/^[0-9a-f]{64}$/);
  // The two servers tag the same message differently — that is the whole
  // side-by-side.
  expect(rawTag).not.toBe(hmacTag);

  // The attacker's entire search space, as the panel states it.
  const range = grab(await flat(page, '#p5'), /somewhere in (\d+)\.\.(\d+) bytes/);
  const low = Number(range[1]);
  const high = Number(range[2]);
  expect(high).toBeGreaterThan(low);

  const accepted: number[] = [];
  for (let guess = low; guess <= high; guess += 1) {
    const verdicts = await forgeAndSubmit(page, guess);
    // HMAC is immune: no guess may ever be accepted by the safe server.
    expect(verdicts.hmac, `HMAC server accepted a forgery at guess ${guess}`).toBe('REJECTED');
    const summary = await flat(page, '#le-summary');
    expect(summary).toContain('SAFE server rejected — HMAC is immune');
    if (verdicts.raw === 'ACCEPTED') {
      accepted.push(guess);
      expect(summary).toContain(`accepted the forgery made with secret-length guess ${guess}`);
    } else {
      expect(verdicts.raw).toBe('REJECTED');
      expect(summary).toContain(`rejected the forgery made with guess ${guess}`);
      expect(summary).toContain('The actual secret length remains hidden');
    }
  }

  // The secret has exactly one length, so exactly one guess can be right — and
  // finding it is what "acceptance confirms that guess" means.
  expect(accepted, 'exactly one guessed secret length must forge successfully').toHaveLength(1);

  // The forged tag is a genuinely different tag from the captured one.
  const forgedTag = grab(
    await text(page, '#le-forge-output'),
    /Forged tag \(broken construction\):\s+([0-9a-f]{64})/,
  )[1];
  expect(forgedTag).not.toBe(rawTag);

  // The layout diagram the README promises, populated from this forgery.
  await expect(page.locator('#le-layout')).toBeVisible();
  await expect(page.locator('#le-seg-msg-detail')).toHaveText('comment=10&uid=7');
  await expect(page.locator('#le-seg-append-detail')).toHaveText('&admin=true');
  await expect(page.locator('#le-seg-glue-detail')).toContainText(`guessed secret = ${high}B`);
});

test('length extension regression: a new forgery drops the previous servers verdicts', async ({
  page,
}) => {
  await open(page);
  await page.locator('#le-capture').click();
  await expect(page.locator('#le-raw-tag')).toHaveText(/^[0-9a-f]{64}$/);

  // Submit one forgery so a BROKEN-server verdict is on screen.
  await forgeAndSubmit(page, 8);
  expect(await flat(page, '#le-summary')).toContain('BROKEN server');

  // Forge again with a different guess. The previous verdict belongs to the
  // previous guess: it must not be restated, and must not be re-attributed to
  // the new guess when the SAFE server is queried on its own.
  await page.locator('#le-guess').fill('9');
  await page.locator('#le-forge').click();
  await expect(page.locator('#le-forge-output')).toContainText('Guessed secret length: 9');
  const afterForge = await flat(page, '#le-summary');
  expect(afterForge, 'a re-forge must clear the stale server verdict').not.toContain('BROKEN server');
  expect(afterForge).toContain('Forged with guessed secret length 9');

  await page.locator('#le-verify-hmac').click();
  await expect(page.locator('#le-verdict-hmac')).toHaveText('REJECTED');
  const afterHmac = await flat(page, '#le-summary');
  // Regression: this used to read "BROKEN server accepted … guess 9" — a verdict
  // for a guess that was never submitted.
  expect(afterHmac, 'the summary must only report submissions actually made').not.toContain(
    'BROKEN server',
  );
  expect(afterHmac).toContain('SAFE server rejected');
});

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

test('timing table: the summary reports the spread of the rows printed above it', async ({ page }) => {
  await open(page);

  await page.locator('#timing-run').click();
  await expect(page.locator('#timing-rows tr')).toHaveCount(3);

  const rows = await page.locator('#timing-rows tr').all();
  const naive: number[] = [];
  const constant: number[] = [];
  for (const row of rows) {
    const cells = await row.locator('td').allInnerTexts();
    expect(cells).toHaveLength(3);
    expect(cells[0]).toMatch(/Mismatch at/);
    naive.push(Number(grab(cells[1]!, /^(\d+\.\d{3}) ms$/)[1]));
    constant.push(Number(grab(cells[2]!, /^(\d+\.\d{3}) ms$/)[1]));
  }

  const summary = await flat(page, '#timing-summary');
  const spreads = grab(summary, /naive (\d+\.\d{3}) ms; full-scan (\d+\.\d{3}) ms/);
  const spread = (values: number[]): number => Math.max(...values) - Math.min(...values);

  // Each printed spread is the spread of the printed rows (allow one display
  // rounding step on each end).
  expect(Math.abs(Number(spreads[1]) - spread(naive))).toBeLessThanOrEqual(0.002);
  expect(Math.abs(Number(spreads[2]) - spread(constant))).toBeLessThanOrEqual(0.002);

  // The comparison sentence must match the two spreads it just reported.
  const flatter = Number(spreads[2]) <= Number(spreads[1]);
  expect(summary).toContain(
    flatter
      ? 'The full-scan comparison was flatter in this run.'
      : 'Measurement noise outweighed the expected shape in this run',
  );
  expect(summary).toContain('JavaScript timing is not a constant-time guarantee.');
});

test('timing attack: byte-by-byte recovery matches the true tag using 256 oracle queries per byte', async ({
  page,
}) => {
  await open(page);

  const wanted = 4;
  await page.locator('#recovery-bytes').fill(String(wanted));
  await page.locator('#recovery-run').click();
  await expect(page.locator('#recovery-output')).toContainText('True tag', { timeout: 60_000 });

  const out = await text(page, '#recovery-output');
  const recovered = grab(out, /Recovered: ([0-9a-f.]+)/)[1];
  const trueTag = grab(out, /True tag:\s+([0-9a-f]{32})/)[1];
  const match = grab(out, /Match for first (\d+) bytes: (✅ YES|❌ NO)/);
  const queries = Number(grab(out, /Total oracle queries: (\d+)/)[1]);

  // The recovered prefix is exactly the true tag's first `wanted` bytes, and the
  // display pads the unknown remainder rather than inventing it.
  expect(recovered).toHaveLength(32);
  expect(recovered.slice(0, wanted * 2)).toBe(trueTag.slice(0, wanted * 2));
  expect(recovered.slice(wanted * 2)).toBe('.'.repeat(32 - wanted * 2));

  // The verdict must match the comparison it reports.
  expect(Number(match[1])).toBe(wanted);
  expect(match[2]).toBe('✅ YES');

  // 256 candidates per byte position — the cost the panel claims.
  expect(queries).toBe(256 * wanted);

  await expect(page.locator('#recovery-status')).toHaveText(
    `Recovered ${wanted} bytes via prefix-match timing leak.`,
  );
  await expect(page.locator('#recovery-bar-fill')).toHaveAttribute('style', /width:\s*100%/);
});

// ---------------------------------------------------------------------------
// Guided tour
// ---------------------------------------------------------------------------

test('guided tour highlights the six panels in pedagogical order', async ({ page }) => {
  await open(page);

  const order = ['p1', 'p5', 'p2', 'p3', 'p4', 'p6'];
  await page.locator('#tour-start').click();

  for (let step = 0; step < order.length; step += 1) {
    const active = page.locator('.panel-active');
    await expect(active).toHaveCount(1);
    await expect(active).toHaveAttribute('id', order[step]!);
    await expect(page.locator('#tour-progress')).toHaveText(`Lesson ${step + 1} of ${order.length}`);
    await expect(page.locator('#tour-title')).toHaveText(new RegExp(`^${step + 1}\\.`));
    if (step < order.length - 1) await page.locator('#tour-next').click();
  }

  // Stepping past the last lesson ends the tour and clears the highlight.
  await page.locator('#tour-next').click();
  await expect(page.locator('.panel-active')).toHaveCount(0);
  await expect(page.locator('#tour-title')).toHaveText('Tour complete — explore freely');
  await expect(page.locator('#tour-progress')).toBeHidden();
});

/* ── The hidden attribute must actually hide ──────────────────────────────
 * `[hidden] { display: none }` is a UA rule using an attribute selector, so any
 * class rule setting `display` outranks it. `.le-layout { display: grid }` did:
 * the length-extension forged-message layout painted at first paint (1105x161)
 * under the caption "What the server actually hashes — SHA-256(secret ∥ forged
 * bytes)", before the attack had been run.
 *
 * Asserted for EVERY element carrying `hidden`, so a future `display` on any
 * hideable class fails here rather than shipping. The count check keeps it from
 * passing vacuously on a page that happens to have no hidden elements.
 */
test('nothing marked hidden is painted', async ({ page }) => {
  await page.goto('.');

  const total = await page.locator('[hidden]').count();
  expect(total, 'no [hidden] elements — this test would prove nothing').toBeGreaterThan(0);

  const painted = await page.evaluate(() =>
    [...document.querySelectorAll('[hidden]')]
      .map((el) => {
        const r = el.getBoundingClientRect();
        return {
          who: el.id || el.className.toString(),
          display: getComputedStyle(el).display,
          size: `${Math.round(r.width)}x${Math.round(r.height)}`,
        };
      })
      .filter((x) => x.display !== 'none'),
  );
  expect(painted, 'elements marked hidden are painted').toEqual([]);
});
