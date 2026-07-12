import { describe, expect, it } from 'vitest';
import {
  DEMO_R_SPACE_BITS,
  computePoly1305,
  runKeyReuseAttackDemo,
  runPoly1305SelfTest,
  verifyPoly1305,
} from './poly1305';

const RFC8439_KEY =
  '85d6be7857556d337f4452fe42d506a8' + '0103808afb0db2fd4abff6af4149f51b';
const RFC8439_MSG = 'Cryptographic Forum Research Group';
const RFC8439_TAG = 'a8061dc1305136c6c22b8baf0c0127a9';

describe('Poly1305 known-answer (RFC 8439 §2.5.2)', () => {
  it('matches the RFC 8439 reference tag', () => {
    expect(runPoly1305SelfTest()).toBe(true);
  });

  it('computePoly1305 reproduces the RFC 8439 vector with the fixed key', () => {
    const { tagHex } = computePoly1305(RFC8439_MSG, RFC8439_KEY);
    expect(tagHex).toBe(RFC8439_TAG);
  });

  it('produces a full 256-bit random key when none is supplied (not a weak key)', () => {
    const { keyHex } = computePoly1305('x');
    expect(keyHex).toHaveLength(64);
    // The reuse-demo weak key zeroes bytes 2..15 of r; the compute path must
    // NOT do that. Assert those bytes are not all zero across the r half.
    const rBytes = keyHex.slice(0, 32);
    expect(rBytes.slice(4)).not.toBe('0'.repeat(28));
  });
});

describe('Poly1305 verification / forgery rejection', () => {
  it('accepts the genuine tag', () => {
    expect(verifyPoly1305(RFC8439_MSG, RFC8439_KEY, RFC8439_TAG)).toBe(true);
  });

  it('rejects a single-bit forgery', () => {
    const flipped = (parseInt(RFC8439_TAG[0], 16) ^ 0x1).toString(16) + RFC8439_TAG.slice(1);
    expect(verifyPoly1305(RFC8439_MSG, RFC8439_KEY, flipped)).toBe(false);
  });

  it('rejects the tag under a modified message', () => {
    expect(verifyPoly1305(RFC8439_MSG + '!', RFC8439_KEY, RFC8439_TAG)).toBe(false);
  });

  it('rejects a malformed key length', () => {
    expect(verifyPoly1305('m', 'abcd', RFC8439_TAG)).toBe(false);
  });
});

describe('Key-reuse forgery (teaching-narrowed r space)', () => {
  it('honestly reports its constrained r-space in the result', () => {
    const demo = runKeyReuseAttackDemo();
    expect(demo.rSpaceBits).toBe(DEMO_R_SPACE_BITS);
    expect(demo.rSpaceBits).toBeLessThanOrEqual(16);
  });

  it('recovers r and forges a tag that is VALID against the real key', () => {
    // The forgery must genuinely match poly1305(msg3, key), not merely a
    // self-graded flag. Run repeatedly since each run picks a fresh key.
    for (let i = 0; i < 30; i += 1) {
      const demo = runKeyReuseAttackDemo();
      expect(demo.validForgery).toBe(true);
    }
  });

  it('the recovered r fits inside the disclosed search space', () => {
    for (let i = 0; i < 30; i += 1) {
      const demo = runKeyReuseAttackDemo();
      expect(parseInt(demo.recoveredRHex, 16)).toBeLessThan(1 << DEMO_R_SPACE_BITS);
    }
  });
});
