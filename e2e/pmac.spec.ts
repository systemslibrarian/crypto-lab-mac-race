import { expect, test, type Locator, type Page } from '@playwright/test';
import { ecb } from '@noble/ciphers/aes.js';
import { createHash } from 'node:crypto';

const MASK = (1n << 128n) - 1n;

test.afterEach(async ({ page }) => {
  if (!process.env.MUTATION_ASSETS) return;
  const assets = JSON.parse(process.env.MUTATION_ASSETS) as Record<string, string>;
  for (const [path, digest] of Object.entries(assets)) {
    const response = await page.request.get(`./assets/${path}`);
    expect(createHash('sha256').update(await response.body()).digest('hex'), `MUTATION_ASSET_MISMATCH ${path}`).toBe(digest);
  }
});

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
const toHex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
const asBig = (value: Uint8Array): bigint => BigInt(`0x${toHex(value) || '0'}`);
const asBlock = (value: bigint): Uint8Array => fromHex((value & MASK).toString(16).padStart(32, '0'));
const xor = (...values: bigint[]): bigint => values.reduce((sum, value) => sum ^ value, 0n);
const mulX = (value: bigint): bigint => ((value << 1n) & MASK) ^ ((value >> 127n) === 1n ? 0x87n : 0n);
const divX = (value: bigint): bigint => (value >> 1n) ^ ((value & 1n) === 1n ? (1n << 127n) | 0x43n : 0n);
const encrypt = (key: Uint8Array, block: bigint): bigint =>
  asBig(ecb(key, { disablePadding: true }).encrypt(asBlock(block)));

function ntz(index: number): number {
  let count = 0;
  while (index % 2 === 0) {
    index /= 2;
    count += 1;
  }
  return count;
}

type ReferencePmac = {
  tag: string;
  l: string;
  lInverse: string;
  padded: string;
  checksum: string;
  finalInput: string;
  lanes: { block: string; offset: string; input: string; output: string }[];
};

/** Independent BigInt/noble reading of Black-Rogaway 2002, not app code. */
function referencePmac(key: Uint8Array, message: Uint8Array, invertedFinalRule = false): ReferencePmac {
  const blockCount = Math.max(1, Math.ceil(message.length / 16));
  const blocks = Array.from({ length: blockCount }, (_, index) => message.slice(index * 16, (index + 1) * 16));
  const l = encrypt(key, 0n);
  const lInverse = divX(l);
  let offset = 0n;
  const outputs: bigint[] = [];
  const lanes: ReferencePmac['lanes'] = [];
  for (let index = 1; index < blockCount; index += 1) {
    let power = l;
    for (let i = 0; i < ntz(index); i += 1) power = mulX(power);
    offset ^= power;
    const block = asBig(blocks[index - 1]!);
    const input = block ^ offset;
    const output = encrypt(key, input);
    outputs.push(output);
    lanes.push({ block: toHex(blocks[index - 1]!), offset: toHex(asBlock(offset)), input: toHex(asBlock(input)), output: toHex(asBlock(output)) });
  }

  const last = blocks.at(-1)!;
  const complete = last.length === 16;
  const paddedBytes = complete
    ? new Uint8Array(last)
    : Uint8Array.from([...last, 0x80, ...new Uint8Array(15 - last.length)]);
  const checksum = xor(...outputs, asBig(paddedBytes));
  const applyInverse = invertedFinalRule ? !complete : complete;
  const finalInput = applyInverse ? checksum ^ lInverse : checksum;
  return {
    tag: toHex(asBlock(encrypt(key, finalInput))),
    l: toHex(asBlock(l)),
    lInverse: toHex(asBlock(lInverse)),
    padded: toHex(paddedBytes),
    checksum: toHex(asBlock(checksum)),
    finalInput: toHex(asBlock(finalInput)),
    lanes,
  };
}

function referenceCmac(key: Uint8Array, message: Uint8Array): string {
  const l = encrypt(key, 0n);
  const k1 = mulX(l);
  const k2 = mulX(k1);
  const count = Math.max(1, Math.ceil(message.length / 16));
  const blocks = Array.from({ length: count }, (_, index) => message.slice(index * 16, (index + 1) * 16));
  let chain = 0n;
  for (let index = 0; index < count - 1; index += 1) chain = encrypt(key, chain ^ asBig(blocks[index]!));
  const last = blocks.at(-1)!;
  const complete = message.length !== 0 && message.length % 16 === 0;
  const padded = complete ? new Uint8Array(last) : Uint8Array.from([...last, 0x80, ...new Uint8Array(15 - last.length)]);
  return toHex(asBlock(encrypt(key, chain ^ asBig(padded) ^ (complete ? k1 : k2))));
}

const value = async (page: Page, name: string): Promise<string> =>
  (await page.locator(`[data-pmac="${name}"]`).innerText()).trim();
const message = async (page: Page, name: 'base-message' | 'candidate-message'): Promise<Uint8Array> =>
  fromHex((await page.locator(`[data-pmac="${name}"]`).getAttribute('data-hex'))!);

async function run(page: Page): Promise<void> {
  await page.locator('#pmac-run').click();
  await expect(page.locator('#pmac-results')).toBeVisible();
  await expect(page.locator('#pmac-status')).not.toContainText('Computing');
}

async function accepted(chip: Locator, expected: boolean): Promise<void> {
  await expect(chip).toHaveText(expected ? 'ACCEPTED' : 'REJECTED');
  await expect(chip).toHaveAttribute('data-accepted', String(expected));
  await expect(chip).toHaveClass(/verdict-accept/);
}

async function expectTrace(page: Page, reference: ReferencePmac): Promise<void> {
  await expect(page.locator('[data-pmac="l"]')).toHaveText(reference.l);
  await expect(page.locator('[data-pmac="l-inverse"]')).toHaveText(reference.lInverse);
  await expect(page.locator('[data-pmac="padded-final"]')).toHaveText(reference.padded);
  await expect(page.locator('[data-pmac="checksum"]')).toHaveText(reference.checksum);
  await expect(page.locator('[data-pmac="final-input"]')).toHaveText(reference.finalInput);
  const rows = page.locator('#pmac-trace tbody tr');
  await expect(rows).toHaveCount(reference.lanes.length);
  for (let i = 0; i < reference.lanes.length; i += 1) {
    const lane = reference.lanes[i]!;
    for (const [field, expected] of Object.entries(lane)) {
      await expect(rows.nth(i).locator(`[data-field="${field}"]`)).toHaveText(expected);
    }
  }
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#p8-title')).toHaveText('PMAC: independent AES lanes');
});

test('PMAC baseline is independently reproducible from every displayed AES input', async ({ page }) => {
  await run(page);
  const pmacKey = fromHex(await value(page, 'pmac-key'));
  const cmacKey = fromHex(await value(page, 'cmac-key'));
  const base = await message(page, 'base-message');
  const candidate = await message(page, 'candidate-message');
  expect(candidate).toEqual(base);
  const reference = referencePmac(pmacKey, candidate);

  expect(await value(page, 'base-tag')).toBe(reference.tag);
  expect(await value(page, 'candidate-tag')).toBe(reference.tag);
  expect(await value(page, 'cmac-tag')).toBe(referenceCmac(cmacKey, base));
  await expectTrace(page, reference);
  await accepted(page.locator('#pmac-original-verdict'), true);
  await accepted(page.locator('#pmac-candidate-verdict'), true);

  const schedule = page.locator('[data-pmac="schedule-summary"]');
  await expect(schedule).toHaveAttribute('data-pmac-work', '4');
  await expect(schedule).toHaveAttribute('data-cmac-work', '4');
  await expect(schedule).toHaveAttribute('data-pmac-span', '2');
  await expect(schedule).toHaveAttribute('data-cmac-span', '4');
  await expect(page.locator('#pmac-waves li')).toHaveCount(2);
  await expect(page.locator('#cmac-waves li')).toHaveCount(4);

  const originalTag = await value(page, 'base-tag');
  await page.locator('#pmac-lanes').selectOption('1');
  await expect(page.locator('#pmac-results')).toBeHidden();
  await run(page);
  expect(await value(page, 'base-tag')).toBe(originalTag);
  await expect(schedule).toHaveAttribute('data-pmac-span', '4');
  await expect(page.locator('#pmac-waves li')).toHaveCount(4);
});

test('content and position changes retire the old tag and accept only a fresh correct tag', async ({ page }) => {
  for (const scenario of ['flip', 'swap'] as const) {
    await page.locator('#pmac-scenario').selectOption(scenario);
    await run(page);
    const key = fromHex(await value(page, 'pmac-key'));
    const base = await message(page, 'base-message');
    const candidate = await message(page, 'candidate-message');
    const baseReference = referencePmac(key, base);
    const candidateReference = referencePmac(key, candidate);
    expect(candidateReference.tag).not.toBe(baseReference.tag);
    expect(await value(page, 'base-tag')).toBe(baseReference.tag);
    expect(await value(page, 'candidate-tag')).toBe(candidateReference.tag);
    await expectTrace(page, candidateReference);
    await accepted(page.locator('#pmac-original-verdict'), false);
    await accepted(page.locator('#pmac-candidate-verdict'), true);

    if (scenario === 'flip') {
      const changed = Array.from(base, (byte, index) => byte ^ candidate[index]!).filter(Boolean);
      expect(changed).toEqual([1]);
    } else {
      expect(toHex(candidate.slice(0, 16))).toBe(toHex(base.slice(16, 32)));
      expect(toHex(candidate.slice(16, 32))).toBe(toHex(base.slice(0, 16)));
    }
  }
});

test('wrong complete and partial final-block rules are computed, then rejected by the correct relation', async ({ page }) => {
  for (const length of ['64', '66'] as const) {
    await page.locator('#pmac-length').selectOption(length);
    await page.locator('#pmac-scenario').selectOption('wrong-final');
    await run(page);
    const key = fromHex(await value(page, 'pmac-key'));
    const bytes = await message(page, 'candidate-message');
    const correct = referencePmac(key, bytes);
    const wrong = referencePmac(key, bytes, true);
    expect(wrong.tag).not.toBe(correct.tag);
    expect(await value(page, 'base-tag')).toBe(correct.tag);
    expect(await value(page, 'candidate-tag')).toBe(wrong.tag);
    await expectTrace(page, wrong);
    await accepted(page.locator('#pmac-original-verdict'), true);
    await accepted(page.locator('#pmac-candidate-verdict'), false);
    await expect(page.locator('[data-pmac="final-rule"]')).toContainText('wrong control');
    if (length === '66') expect(wrong.padded).toBe('40418000000000000000000000000000');
  }
});

test('edits, key rotation and delayed obsolete AES work cannot leave current claims on screen', async ({ page }) => {
  await run(page);
  const firstKey = await value(page, 'pmac-key');
  await page.locator('#pmac-scenario').dispatchEvent('change');
  await expect(page.locator('#pmac-results')).toBeVisible();

  await page.locator('#pmac-lanes').selectOption('2');
  await expect(page.locator('#pmac-results')).toBeHidden();
  await expect(page.locator('#pmac-status')).toContainText('retired');
  await run(page);
  await page.locator('#pmac-rotate').click();
  await expect(page.locator('#pmac-results')).toBeHidden();
  await run(page);
  expect(await value(page, 'pmac-key')).not.toBe(firstKey);

  await page.reload();
  await page.evaluate(() => {
    const subtle = crypto.subtle;
    const original = subtle.encrypt.bind(subtle);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    (window as unknown as { releasePmacAes: () => void }).releasePmacAes = release;
    Object.defineProperty(subtle, 'encrypt', {
      configurable: true,
      value: (...args: Parameters<SubtleCrypto['encrypt']>) => gate.then(() => original(...args)),
    });
  });
  await page.locator('#pmac-run').click();
  await expect(page.locator('#pmac-status')).toContainText('Computing');
  await page.locator('#pmac-scenario').selectOption('flip');
  await expect(page.locator('#pmac-results')).toBeHidden();
  await page.evaluate(() => (window as unknown as { releasePmacAes: () => void }).releasePmacAes());
  await run(page);
  expect(await message(page, 'candidate-message')).not.toEqual(await message(page, 'base-message'));
  await accepted(page.locator('#pmac-original-verdict'), false);
  await accepted(page.locator('#pmac-candidate-verdict'), true);
});

test('variant, standardization and performance boundaries remain visible with primary sources', async ({ page }) => {
  const panel = page.locator('#p8');
  await expect(panel).toContainText('2002 Black–Rogaway PMAC definition');
  await expect(panel).toContainText('not a measured multicore speedup');
  await expect(panel).toContainText('does not itself prove the paper\'s PRF theorem');
  await expect(panel).toContainText('public test material');
  await expect(page.locator('#p6')).toContainText('not NIST-standardized');
  await expect(panel.locator('a[href="https://www.cs.ucdavis.edu/~rogaway/papers/pmac.pdf"]')).toHaveCount(1);
  await expect(panel.locator('a[href="https://www.cs.ucdavis.edu/~rogaway/ocb/pmac128.txt"]')).toHaveCount(1);
  await expect(panel.locator('a[href="https://www.cs.ucdavis.edu/~rogaway/ocb/pmac256.txt"]')).toHaveCount(1);
});
