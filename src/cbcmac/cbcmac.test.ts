import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { cmac, ecb } from '@noble/ciphers/aes.js';
import { cmacBytes, computeCmac } from '../cmac';
import { aesBlockEncrypt } from './aesBlock';
import { EMPTY_MESSAGE, hex, lengthBlock, LENGTH_MISMATCH, NOT_BLOCK_ALIGNED, prependLengthCbcMac, rawCbcMac, TAG_MISMATCH, unhex, verifyAnyLength, verifyFixedLength, verifyPrepended } from './cbcmac';
import { spliceOne, spliceTwo } from './forge';
import { makeLessonOracles, makeMacOracle } from './oracle';

const K128 = unhex('2b7e151628aed2a6abf7158809cf4f3c');
const K256 = unhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
const MESSAGE = unhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
function independentRaw(key: Uint8Array, message: Uint8Array): Uint8Array {
  let state: Uint8Array = new Uint8Array(16);
  for (let offset = 0; offset < message.length; offset += 16) state = ecb(key, { disablePadding: true }).encrypt(Uint8Array.from({ length: 16 }, (_, i) => state[i]! ^ message[offset + i]!));
  return state;
}

describe('published AES/CMAC pins through the original WebCrypto path', () => {
  it('NIST SP 800-38A F.1.1 and F.1.5 ECB block one for AES-128 and AES-256', async () => {
    expect(hex(await aesBlockEncrypt(K128, MESSAGE.slice(0, 16)))).toBe('3ad77bb40d7a3660a89ecaf32466ef97');
    expect(hex(await aesBlockEncrypt(K256, MESSAGE.slice(0, 16)))).toBe('f3eed1bdb5d2a03c064b5a7e3db181f8');
  });
  // RFC 4493 §4 examples 1–4: 40-byte example, unlike the CSRC 20-byte example.
  for (const [length, tag] of [[0, 'bb1d6929e95937287fa37d129b756746'], [16, '070a16b46b4d4144f79bdd9dd04a287c'], [40, 'dfa66747de9ae63030ca32611497c827'], [64, '51f0bebf7e3b9d92fc49741779363cfe']] as const) {
    it(`RFC 4493 AES-128 ${length}-byte message`, async () => expect((await cmacBytes(K128, MESSAGE.slice(0, length))).tagHex).toBe(tag));
  }
  // CSRC AES_CMAC.pdf CMAC-AES256 examples 1–4, fetched 2026-10-20.
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
  for (const [length, tag] of [[0, '028962f61b7bf89efc6b551f4667d983'], [16, '28a7023f452e8f82bd4bf28d8c37c35c'], [20, '156727dc0878944a023c1fe03bad6d93'], [64, 'e1992190549f6ed5696a2c056c315410']] as const) {
    it(`CSRC AES-256 ${length}-byte message`, async () => expect((await cmacBytes(K256, MESSAGE.slice(0, length))).tagHex).toBe(tag));
  }
  it('pins both RFC 4493 subkeys', async () => {
    const { details } = await cmacBytes(K128, new Uint8Array());
    expect(details.k1Hex).toBe('fbeed618357133667c85e08f7236a8de'); expect(details.k2Hex).toBe('f7ddac306ae266ccf90bc11ee46d513b');
  });
  it('derives a raw-CBC-MAC check from published CBC encryption, with honest attribution', async () => {
    // Derived from SP 800-38A F.2.1 CBC encryption by folding its IV into the first plaintext block; not a published CBC-MAC vector.
    const folded = new Uint8Array(MESSAGE); folded.set(unhex('6bc0bce12a459991e134741a7f9e1925'));
    expect(hex(await rawCbcMac(K128, folded))).toBe('3ff1caa1681fac09120eca307586e1a7');
    const source = readFileSync(new URL('./cbcmac.test.ts', import.meta.url), 'utf8');
    expect(source.split('\n').some(line => line.trimStart() === '// Derived from SP 800-38A F.2.1 CBC encryption by folding its IV into the first plaintext block; not a published CBC-MAC vector.')).toBe(true);
  });
});

describe('independent properties and real verifier attacks', () => {
  it('cross-checks 100 random raw chains (1–8 blocks) and CMAC for lengths 0–100 with noble', async () => {
    for (let i = 0; i < 101; i++) {
      const key = random(i % 2 ? 16 : 32), m = random(i), blocks = random(16 * (1 + i % 8));
      expect((await cmacBytes(key, m)).tagHex).toBe(hex(cmac(m, key)));
      if (i < 100) expect(await rawCbcMac(key, blocks)).toEqual(independentRaw(key, blocks));
    }
  });
  it('rechecks one- and two-query splice algebra for 100 random keys and both fixes', async () => {
    for (let i = 0; i < 100; i++) {
      const key = random(i % 2 ? 16 : 32), m = random(16), mPrime = random(16 * (1 + i % 8));
      const tag = await rawCbcMac(key, m), other = await rawCbcMac(key, mPrime);
      for (const [forged, target, original] of [[spliceOne(m, tag), tag, m], [spliceTwo(m, tag, mPrime), other, mPrime]] as const) {
        expect((await verifyAnyLength(key, forged, target)).accepted).toBe(true);
        expect((await verifyFixedLength(key, forged, target, 16)).code).toBe(LENGTH_MISMATCH);
        const prefixTag = await prependLengthCbcMac(key, original);
        expect((await verifyPrepended(key, forged, prefixTag)).code).toBe(TAG_MISMATCH);
        expect((await cmacBytes(key, forged)).tagHex).not.toBe(hex(target));
        // Against CMAC's OWN oracle, the attacker sees a CMAC tag, not raw AES(m).
        const ownTag = unhex((await cmacBytes(key, m)).tagHex), ownTarget = unhex((await cmacBytes(key, original)).tagHex);
        const ownForged = original === m ? spliceOne(m, ownTag) : spliceTwo(m, ownTag, original);
        expect((await cmacBytes(key, ownForged)).tagHex).not.toBe(hex(ownTarget));
      }
    }
  }, 20000);
  it('general two-query splice supports multi-block first messages and a one-block second message', async () => {
    for (let n = 1; n <= 8; n++) {
      const key = random(32), m = random(16 * n), other = random(16), tag = await rawCbcMac(key, m), target = await rawCbcMac(key, other);
      expect((await verifyAnyLength(key, spliceTwo(m, tag, other), target)).accepted).toBe(true);
      if (n === 1) expect(spliceTwo(m, tag, m)).toEqual(spliceOne(m, tag));
    }
  });
  it('agreed receiver length alone cannot fix a sender that tags a different length', async () => {
    const key = random(32), m = random(16), tag = await rawCbcMac(key, m);
    expect((await verifyFixedLength(key, spliceOne(m, tag), tag, 32)).accepted).toBe(true);
    const fixed = makeMacOracle('fixed', () => 32);
    await expect(fixed.mac(m)).rejects.toThrow(LENGTH_MISMATCH);
  });
  it('encodes byte lengths in one 128-bit BE block and validates raw/forgery boundaries', async () => {
    expect(hex(lengthBlock(16))).toBe('00000000000000000000000000000010');
    expect(hex(lengthBlock(256))).toBe('00000000000000000000000000000100');
    await expect(rawCbcMac(K128, new Uint8Array())).rejects.toThrow(EMPTY_MESSAGE);
    await expect(rawCbcMac(K128, new Uint8Array(17))).rejects.toThrow('Received 17 bytes; next valid length is 32');
    expect((await verifyAnyLength(K128, new Uint8Array(17), new Uint8Array(16))).code).toBe(NOT_BLOCK_ALIGNED);
    expect((await verifyPrepended(K128, new Uint8Array(0), new Uint8Array(16))).code).toBe(EMPTY_MESSAGE);
    await expect(aesBlockEncrypt(new Uint8Array(24), new Uint8Array(16))).rejects.toThrow('16- or 32');
    await expect(cmacBytes(new Uint8Array(15), MESSAGE)).rejects.toThrow('16- or 32');
    expect(() => spliceOne(new Uint8Array(32), new Uint8Array(16))).toThrow('one 16-byte');
    expect(() => spliceTwo(new Uint8Array(16), new Uint8Array(15), new Uint8Array(16))).toThrow('two 16-byte');
  });
  it('oracle closures expose only mac/verify, return detached bytes and recompute; raw/fixed share their key', async () => {
    const oracles = makeLessonOracles(() => 16), m = random(16);
    for (const oracle of Object.values(oracles)) {
      expect(Object.keys(oracle).sort()).toEqual(['mac', 'verify']);
      const tag = await oracle.mac(m); expect((await oracle.verify(m, tag)).accepted).toBe(true);
      tag[0] ^= 1; expect((await oracle.verify(m, tag)).accepted).toBe(false);
    }
    const tag = await oracles.raw.mac(m); expect((await oracles.fixed.verify(m, tag)).accepted).toBe(true);
    expect(spliceOne.length).toBe(2); expect(spliceTwo.length).toBe(3);
  });
  it('documents why giving raw-CBC-MAC and CMAC oracles the same key invalidates an independent-scheme comparison', async () => {
    const m = random(16), raw = await rawCbcMac(K128, m), cmacTag = await cmacBytes(K128, m);
    // With BOTH oracles and one key, raw AES(m) cancels the chain even under CMAC.
    const crossProtocol = spliceOne(m, raw);
    expect((await cmacBytes(K128, crossProtocol)).tagHex).toBe(cmacTag.tagHex);
    expect(hex(cmac(crossProtocol, K128))).toBe(cmacTag.tagHex);
  });
  it('the additive bytes API preserves the old passphrase-to-AES-256 behavior', async () => {
    const phrase = '  preserve whitespace  ', message = 'existing API';
    const key = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(phrase)));
    expect(await computeCmac(message, phrase)).toEqual(await cmacBytes(key, new TextEncoder().encode(message)));
  });
});
