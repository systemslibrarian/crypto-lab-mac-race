import { ecb } from '@noble/ciphers/aes.js';
import { describe, expect, it } from 'vitest';
import { hex, unhex } from '../cbcmac/cbcmac';
import {
  divideByX,
  multiplyByX,
  pmac2002,
  pmacWrongFinalRuleForLesson,
  trailingZeroBits,
  verifyPmac2002
} from './pmac';
import { modelPmacVsCmac } from './schedule';

const KEY128 = unhex('000102030405060708090a0b0c0d0e0f');
const KEY256 = unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const ascending = (length: number): Uint8Array => Uint8Array.from({ length }, (_, index) => index & 0xff);
const zeroes = (length: number): Uint8Array => new Uint8Array(length);

// Author-hosted PMAC-AES vectors linked from Rogaway's PMAC test-vector page.
// https://www.cs.ucdavis.edu/~rogaway/ocb/pmac-test.htm
const VECTORS_128 = [
  [0, '4399572cd6ea5341b8d35876a7098af7'],
  [3, '256ba5193c1b991b4df0c51f388a9e27'],
  [16, 'ebbd822fa458daf6dfdad7c27da76338'],
  [20, '0412ca150bbf79058d8c75a58c993f55'],
  [32, 'e97ac04e9e5e3399ce5355cd7407bc75'],
  [34, '5cba7d5eb24f7c86ccc54604e53d5512']
] as const;
const VECTORS_256 = [
  [0, 'e620f52fe75bbe87ab758c0624943d8b'],
  [3, 'ffe124cc152cfb2bf1ef5409333c1c9a'],
  [16, '853fdbf3f91dcd36380d698a64770bab'],
  [20, '7711395fbe9dec19861aeb96e052cd1b'],
  [32, '08fa25c28678c84d383130653e77f4c0'],
  [34, 'edd8a05f4b66761f9eee4feb4ed0c3a1']
] as const;

describe('Black–Rogaway 2002 PMAC official vectors', () => {
  for (const [length, tag] of VECTORS_128) {
    it(`PMAC-AES-128 ${length} bytes`, async () => expect((await pmac2002(KEY128, ascending(length))).tagHex).toBe(tag));
  }
  for (const [length, tag] of VECTORS_256) {
    it(`PMAC-AES-256 ${length} bytes`, async () => expect((await pmac2002(KEY256, ascending(length))).tagHex).toBe(tag));
  }
  it('matches the official 1000-byte zero vectors', async () => {
    expect((await pmac2002(KEY128, zeroes(1000))).tagHex).toBe('c2c9fa1d9985f6f0d2aff915a0e8d910');
    expect((await pmac2002(KEY256, zeroes(1000))).tagHex).toBe('69aa77f231eb0cdff960f5561d29a96e');
  });
});

const MASK128 = (1n << 128n) - 1n;
const bytesToBigInt = (bytes: Uint8Array): bigint => BigInt(`0x${hex(bytes) || '0'}`);
const bigIntToBlock = (value: bigint): Uint8Array => unhex((value & MASK128).toString(16).padStart(32, '0'));
const mulXReference = (value: bigint): bigint => ((value << 1n) & MASK128) ^ ((value >> 127n) ? 0x87n : 0n);
const divXReference = (value: bigint): bigint => (value >> 1n) ^ ((value & 1n) ? ((1n << 127n) | 0x43n) : 0n);
const xorBig = (...values: bigint[]): bigint => values.reduce((sum, value) => sum ^ value, 0n);
const encryptReference = (key: Uint8Array, block: bigint): bigint => bytesToBigInt(ecb(key, { disablePadding: true }).encrypt(bigIntToBlock(block)));

function referencePmac(key: Uint8Array, message: Uint8Array): string {
  const count = Math.max(1, Math.ceil(message.length / 16));
  const blocks = Array.from({ length: count }, (_, index) => message.slice(index * 16, (index + 1) * 16));
  const l = encryptReference(key, 0n);
  let offset = 0n;
  const outputs: bigint[] = [];
  for (let i = 1; i < count; i += 1) {
    let power = l;
    for (let j = 0; j < trailingZeroBits(i); j += 1) power = mulXReference(power);
    offset ^= power;
    outputs.push(encryptReference(key, bytesToBigInt(blocks[i - 1]!) ^ offset));
  }
  const last = blocks.at(-1)!;
  const complete = last.length === 16;
  const padded = complete ? bytesToBigInt(last) : bytesToBigInt(Uint8Array.from([...last, 0x80, ...new Uint8Array(15 - last.length)]));
  let finalInput = xorBig(...outputs, padded);
  if (complete) finalInput ^= divXReference(l);
  return hex(bigIntToBlock(encryptReference(key, finalInput)));
}

describe('independent PMAC arithmetic and controls', () => {
  it('cross-checks byte arithmetic against a BigInt/noble reference for varied lengths and keys', async () => {
    for (let length = 0; length <= 257; length += 1) {
      const key = length % 2 ? KEY128 : KEY256;
      const message = crypto.getRandomValues(new Uint8Array(length));
      expect((await pmac2002(key, message)).tagHex).toBe(referencePmac(key, message));
    }
  }, 20000);

  it('implements x and x^-1 as inverse field operations at carry boundaries', () => {
    for (const value of [0n, 1n, 2n, 0x80n, 1n << 127n, MASK128, 0x123456789abcdefn]) {
      const block = bigIntToBlock(value);
      expect(bytesToBigInt(multiplyByX(block))).toBe(mulXReference(value));
      expect(bytesToBigInt(divideByX(block))).toBe(divXReference(value));
      expect(divideByX(multiplyByX(block))).toEqual(block);
      expect(multiplyByX(divideByX(block))).toEqual(block);
    }
    expect([1, 2, 3, 4, 8, 12, 16].map(trailingZeroBits)).toEqual([0, 1, 0, 2, 3, 2, 4]);
    expect(() => trailingZeroBits(0)).toThrow('positive safe integers');
  });

  it('derives every lane input before independent AES calls and records the final dependency', async () => {
    const result = await pmac2002(KEY128, ascending(64));
    expect(result.details.blockCount).toBe(4);
    expect(result.details.lanes).toHaveLength(3);
    expect(result.details.lanes.map((lane) => lane.index)).toEqual([1, 2, 3]);
    expect(new Set(result.details.lanes.map((lane) => lane.offsetHex)).size).toBe(3);
    expect(result.details.aesCallsPerMessage).toBe(4);
    expect(result.details.finalRule).toBe('complete: XOR L·x^-1');
  });

  it('accepts genuine tags and rejects content, position and final-rule mutations', async () => {
    const message = ascending(64);
    const genuine = await pmac2002(KEY256, message);
    expect(await verifyPmac2002(KEY256, message, genuine.tag)).toBe(true);

    const flipped = new Uint8Array(message);
    flipped[16] ^= 1;
    expect(await verifyPmac2002(KEY256, flipped, genuine.tag)).toBe(false);
    expect((await pmac2002(KEY256, flipped)).tagHex).not.toBe(genuine.tagHex);

    const swapped = new Uint8Array(message);
    swapped.set(message.slice(16, 32), 0);
    swapped.set(message.slice(0, 16), 16);
    expect(await verifyPmac2002(KEY256, swapped, genuine.tag)).toBe(false);
    expect((await pmac2002(KEY256, swapped)).tagHex).not.toBe(genuine.tagHex);

    const wrong = await pmacWrongFinalRuleForLesson(KEY256, message);
    expect(wrong.tagHex).not.toBe(genuine.tagHex);
    expect(await verifyPmac2002(KEY256, message, wrong.tag)).toBe(false);
  });

  it('keeps complete and partial final-block rules distinct', async () => {
    const complete = await pmac2002(KEY128, ascending(32));
    const partial = await pmac2002(KEY128, ascending(34));
    expect(complete.details.finalRule).toBe('complete: XOR L·x^-1');
    expect(partial.details.finalRule).toBe('partial: 10* padding, no L·x^-1');
    expect(partial.details.paddedFinalBlockHex).toBe('20218000000000000000000000000000');
    expect((await pmacWrongFinalRuleForLesson(KEY128, ascending(34))).tagHex).not.toBe(partial.tagHex);
  });

  it('rejects unsupported keys and malformed candidate lengths without throwing', async () => {
    await expect(pmac2002(new Uint8Array(24), ascending(16))).rejects.toThrow('16- or 32-byte key');
    expect(await verifyPmac2002(KEY128, ascending(16), new Uint8Array(15))).toBe(false);
  });
});

describe('PMAC versus CMAC AES dependency model', () => {
  it('uses equal per-message AES work but exposes the correct dependency span', () => {
    const one = modelPmacVsCmac(64, 1);
    expect(one.pmac.aesWork).toBe(4);
    expect(one.cmac.aesWork).toBe(4);
    expect(one.pmac.aesSpan).toBe(4);
    expect(one.cmac.aesSpan).toBe(4);

    const four = modelPmacVsCmac(64, 4);
    expect(four.pmac.aesSpan).toBe(2);
    expect(four.cmac.aesSpan).toBe(4);
    expect(four.pmac.waves[0]!.tasks.map((task) => task.block)).toEqual([1, 2, 3]);
    expect(four.pmac.waves[1]!.tasks[0]!.dependsOn).toEqual(['PMAC block 1', 'PMAC block 2', 'PMAC block 3']);
    expect(four.keySetupAesCallsEach).toBe(1);
  });

  it('handles empty, one-block, partial and lane-boundary cases without inventing speed measurements', () => {
    for (const bytes of [0, 1, 15, 16]) {
      const schedule = modelPmacVsCmac(bytes, 8);
      expect(schedule.blockCount).toBe(1);
      expect(schedule.pmac.aesWork).toBe(1);
      expect(schedule.pmac.aesSpan).toBe(1);
      expect(schedule.cmac.aesSpan).toBe(1);
    }
    expect(modelPmacVsCmac(65, 2).pmac.aesSpan).toBe(3);
    expect(() => modelPmacVsCmac(-1, 1)).toThrow('nonnegative safe integer');
    expect(() => modelPmacVsCmac(16, 0)).toThrow('integer from 1 to 64');
    expect(() => modelPmacVsCmac(16, 65)).toThrow('integer from 1 to 64');
  });
});
