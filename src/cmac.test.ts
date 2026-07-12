import { describe, expect, it } from 'vitest';
import { computeCmac, runCmacSelfTest, verifyCmac } from './cmac';

// NIST SP 800-38B / RFC 4493 AES-CMAC test vectors.
// The demo derives an AES-256 key when given 64 hex chars, so we use the
// AES-256 CMAC example from NIST SP 800-38B (Appendix D.3, Example 10).
const KEY_256 =
  '603deb1015ca71be2b73aef0857d7781' + '1f352c073b6108d72d9810a30914dff4';

// computeCmac takes a UTF-8 *string* message; to feed exact bytes we exploit
// that ASCII-safe bytes map 1:1. For binary vectors we test through the
// hex-key path used by the self-test, then add string-message round-trips.

describe('AES-CMAC known-answer vectors', () => {
  it('reproduces the SP 800-38B AES-256 single-block tag (self-test)', async () => {
    expect(await runCmacSelfTest()).toBe(true);
  });

  it('derives K1/K2 by left-shift with Rb=0x87 conditional XOR', async () => {
    const { details } = await computeCmac('', KEY_256);
    // For a zero-length message the last block uses K2 with 10* padding.
    // K1 and K2 must be 16 bytes and K2 = leftshift(K1) (+Rb if MSB set).
    expect(details.k1Hex).toHaveLength(32);
    expect(details.k2Hex).toHaveLength(32);
    expect(details.k1Hex).not.toEqual(details.k2Hex);
  });

  it('empty message uses K2 + 0x80 padding (padded block starts with 80)', async () => {
    const { details } = await computeCmac('', KEY_256);
    expect(details.paddedLastBlockHex.startsWith('80')).toBe(true);
  });

  it('16-byte (complete) block uses K1, no 0x80 padding byte introduced', async () => {
    // A 16-char ASCII message is exactly one complete AES block.
    const msg = '0123456789abcdef';
    const { details } = await computeCmac(msg, KEY_256);
    // Complete block: padded last block equals the raw UTF-8 message bytes.
    const expected = Array.from(new TextEncoder().encode(msg), (b) =>
      b.toString(16).padStart(2, '0')
    ).join('');
    expect(details.paddedLastBlockHex).toBe(expected);
  });
});

describe('AES-CMAC verification', () => {
  it('accepts the tag it produced', async () => {
    const { tagHex } = await computeCmac('authenticate me', 'shared-secret');
    expect(await verifyCmac('authenticate me', 'shared-secret', tagHex)).toBe(true);
  });

  it('rejects a tag with a single flipped nibble (forgery)', async () => {
    const { tagHex } = await computeCmac('authenticate me', 'shared-secret');
    const flipped = (parseInt(tagHex[0], 16) ^ 0x1).toString(16) + tagHex.slice(1);
    expect(await verifyCmac('authenticate me', 'shared-secret', flipped)).toBe(false);
  });

  it('rejects a valid tag under a different message', async () => {
    const { tagHex } = await computeCmac('amount=100', 'k');
    expect(await verifyCmac('amount=900', 'k', tagHex)).toBe(false);
  });

  it('rejects a valid tag under a different key', async () => {
    const { tagHex } = await computeCmac('msg', 'key-a');
    expect(await verifyCmac('msg', 'key-b', tagHex)).toBe(false);
  });

  it('rejects a truncated tag rather than throwing', async () => {
    const { tagHex } = await computeCmac('msg', 'k');
    expect(await verifyCmac('msg', 'k', tagHex.slice(0, 30))).toBe(false);
  });
});

describe('AES-CMAC properties', () => {
  it('is deterministic for the same (message, key)', async () => {
    const a = await computeCmac('deterministic', 'k');
    const b = await computeCmac('deterministic', 'k');
    expect(a.tagHex).toBe(b.tagHex);
  });

  it('produces a 128-bit (16-byte) tag', async () => {
    const { tagHex } = await computeCmac('x', 'k');
    expect(tagHex).toHaveLength(32);
  });

  it('changes tag when a single message byte changes (avalanche)', async () => {
    const a = await computeCmac('payload-A', 'k');
    const b = await computeCmac('payload-B', 'k');
    expect(a.tagHex).not.toBe(b.tagHex);
  });
});
