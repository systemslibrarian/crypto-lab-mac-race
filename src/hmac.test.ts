import { describe, expect, it } from 'vitest';
import { computeHmac, runHmacSelfTest, verifyHmac } from './hmac';

// RFC 4231 test case 1: key = 0x0b×20, data = "Hi There".
const RFC4231_KEY_HEX = '0b'.repeat(20);
const RFC4231_MSG = 'Hi There';
const RFC4231_256 = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';
const RFC4231_512 =
  '87aa7cdea5ef619d4ff0b4241a1d6cb0' +
  '2379f4e2ce4ec2787ad0b30545e17cde' +
  'daa833b7d6b8a702038b274eaea3f4e4' +
  'be9d914eeb61f1702e696c203a126854';

describe('HMAC known-answer vectors (RFC 4231)', () => {
  it('passes the built-in self-test', async () => {
    expect(await runHmacSelfTest()).toBe(true);
  });

  it('HMAC-SHA-256 matches RFC 4231 test case 1', async () => {
    const { macHex } = await computeHmac(RFC4231_MSG, RFC4231_KEY_HEX, 'SHA-256');
    expect(macHex).toBe(RFC4231_256);
  });

  it('HMAC-SHA-512 matches RFC 4231 test case 1', async () => {
    const { macHex } = await computeHmac(RFC4231_MSG, RFC4231_KEY_HEX, 'SHA-512');
    expect(macHex).toBe(RFC4231_512);
  });

  it('exposes ipad/opad derived from the block-sized key', async () => {
    const { visual } = await computeHmac(RFC4231_MSG, RFC4231_KEY_HEX, 'SHA-256');
    // ipad/opad are the normalized key XORed with 0x36 / 0x5c over 64 bytes.
    expect(visual.ipadHex).toHaveLength(128);
    expect(visual.opadHex).toHaveLength(128);
    expect(visual.outerHashHex).toBe(RFC4231_256);
  });
});

describe('HMAC verification / forgery rejection', () => {
  it('accepts the genuine tag', async () => {
    expect(await verifyHmac(RFC4231_MSG, RFC4231_KEY_HEX, 'SHA-256', RFC4231_256)).toBe(true);
  });

  it('rejects a flipped tag', async () => {
    const flipped = (parseInt(RFC4231_256[0], 16) ^ 0x1).toString(16) + RFC4231_256.slice(1);
    expect(await verifyHmac(RFC4231_MSG, RFC4231_KEY_HEX, 'SHA-256', flipped)).toBe(false);
  });

  it('rejects the correct SHA-256 tag when asked to verify as SHA-512', async () => {
    expect(await verifyHmac(RFC4231_MSG, RFC4231_KEY_HEX, 'SHA-512', RFC4231_256)).toBe(false);
  });

  it('rejects a tag for a different key', async () => {
    expect(await verifyHmac(RFC4231_MSG, 'cc'.repeat(20), 'SHA-256', RFC4231_256)).toBe(false);
  });
});
