import { describe, expect, it } from 'vitest';
import { hexToBytes, bytesToHex } from '@noble/ciphers/utils.js';
import {
  computeGhash,
  gf128Mul,
  runGhashReuseAttackDemo,
  runGhashSelfTest,
  verifyGhash,
} from './ghash';

describe('GF(2^128) multiplication (GHASH core)', () => {
  it('matches the canonical H·X test vector', () => {
    // From the GCM spec worked example (H, first ciphertext block).
    expect(runGhashSelfTest()).toBe(true);
  });

  it('has 1 (0x80…00, the field identity) as multiplicative identity', () => {
    const one = new Uint8Array(16);
    one[0] = 0x80;
    const x = hexToBytes('0388dace60b6a392f328c2b971b2fe78');
    expect(bytesToHex(gf128Mul(x, one))).toBe(bytesToHex(x));
  });

  it('is commutative', () => {
    const a = hexToBytes('66e94bd4ef8a2c3b884cfa59ca342b2e');
    const b = hexToBytes('0388dace60b6a392f328c2b971b2fe78');
    expect(bytesToHex(gf128Mul(a, b))).toBe(bytesToHex(gf128Mul(b, a)));
  });

  it('multiplication by zero yields zero', () => {
    const zero = new Uint8Array(16);
    const x = hexToBytes('66e94bd4ef8a2c3b884cfa59ca342b2e');
    expect(bytesToHex(gf128Mul(x, zero))).toBe(bytesToHex(zero));
  });
});

describe('GHASH computation', () => {
  it('is deterministic for a fixed key', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const a = await computeGhash('0388dace60b6a392f328c2b971b2fe78', key);
    const b = await computeGhash('0388dace60b6a392f328c2b971b2fe78', key);
    expect(a.yHex).toBe(b.yHex);
    expect(a.hHex).toBe(b.hHex);
  });

  it('accepts its own tag and rejects a flipped one', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const ct = '0388dace60b6a392f328c2b971b2fe78';
    const { yHex } = await computeGhash(ct, key);
    expect(await verifyGhash(ct, key, yHex)).toBe(true);
    const forged = (parseInt(yHex[0], 16) ^ 0x8).toString(16) + yHex.slice(1);
    expect(await verifyGhash(ct, key, forged)).toBe(false);
  });
});

describe('Forbidden Attack (nonce reuse) — live H recovery', () => {
  it('recovers the true, live-derived H from two reused-nonce tags', async () => {
    // Run several times: the demo generates a fresh random key each call,
    // so this also fuzzes the algebra across many H values.
    for (let i = 0; i < 25; i += 1) {
      const demo = await runGhashReuseAttackDemo();
      expect(demo.hMatchesTrue).toBe(true);
    }
  });

  it('produces a forged tag the server (holding true H) accepts', async () => {
    for (let i = 0; i < 25; i += 1) {
      const demo = await runGhashReuseAttackDemo();
      expect(demo.serverAccepts).toBe(true);
      expect(demo.forgedValid).toBe(true);
    }
  });

  it('does not hard-code its inputs — c1/c2 vary between runs', async () => {
    const a = await runGhashReuseAttackDemo();
    const b = await runGhashReuseAttackDemo();
    // Overwhelmingly likely to differ; if this ever collides the RNG is broken.
    expect(a.c1Hex === b.c1Hex && a.c2Hex === b.c2Hex).toBe(false);
  });

  it('the recovered-H equation ΔT = ΔC·H holds', async () => {
    const d = await runGhashReuseAttackDemo();
    const deltaC = hexToBytes(d.deltaCHex);
    const recovered = hexToBytes(d.recoveredHHex);
    // ΔC · H should reproduce ΔT.
    expect(bytesToHex(gf128Mul(deltaC, recovered))).toBe(d.deltaTHex);
  });
});
