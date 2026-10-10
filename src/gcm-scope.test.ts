import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/ciphers/utils.js';
import { computeGhash, gf128Mul } from './ghash';

// Published AES-GCM worked example, independently retained by BoringSSL:
// https://boringssl.googlesource.com/boringssl/+/c63fadbde60a2224c22189d14c4001bbd2a3a629/src/crypto/cipher/test/cipher_tests.txt
// zero 128-bit key, zero 96-bit IV,
// zero 128-bit plaintext, no AAD, full-length tag. These are ordinary
// known-answer verification controls, not key recovery or a new forgery demo.
const ciphertext = '0388dace60b6a392f328c2b971b2fe78';
const tag = 'ab6e47d42cec13bdf53a67b21257bddf';
const h = '66e94bd4ef8a2c3b884cfa59ca342b2e';

async function decrypt(candidate: string, iv = new Uint8Array(12)) {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(16), 'AES-GCM', false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, key,
    hexToBytes(ciphertext + candidate) as BufferSource);
}

describe('Raw field products are not GCM authentication tags', () => {
  it('accepts the published full GCM tag and rejects changed tag or nonce', async () => {
    expect(bytesToHex(new Uint8Array(await decrypt(tag)))).toBe('00'.repeat(16));
    await expect(decrypt('0' + tag.slice(1))).rejects.toThrow();
    const otherNonce = new Uint8Array(12); otherNonce[11] = 1;
    await expect(decrypt(tag, otherNonce)).rejects.toThrow();
  });

  it('includes the length block in the compute panel, without pretending to include the GCM mask', async () => {
    const result = await computeGhash(ciphertext, '00'.repeat(16));
    expect(result.hHex).toBe(h);
    expect(result.steps).toEqual(['5e2ec746917062882c85b0685353deb7', 'f38cbb1ad69223dcc3457ae5b6b0f885']);
    expect(result.yHex).toBe(result.steps[1]);
    expect(result.yHex).not.toBe(tag);
    const rawProduct = bytesToHex(gf128Mul(hexToBytes(ciphertext), hexToBytes(h)));
    expect(rawProduct).toBe(result.steps[0]);
    await expect(decrypt(rawProduct)).rejects.toThrow();
    await expect(decrypt(result.yHex)).rejects.toThrow();
  });
});
