import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { crc32, crc32ReverseStep, crc32Step } from './crc32';
import { crcReceiverAccepts } from './receiver';
import { forceCrc, repairCrc } from './forge';
import { createHmacReceiver } from './hmac-receiver';
import { computeHmac } from '../hmac';

const enc = new TextEncoder();
const u32le = (n: number) => new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, n >>> 24]);
const join = (a: Uint8Array, b: Uint8Array) => new Uint8Array([...a, ...b]);

describe('CRC-32/ISO-HDLC', () => {
  it('matches the catalogue check value and independent long vectors', () => {
    expect(crc32(enc.encode('123456789'))).toBe(0xcbf43926);
    expect(crc32(enc.encode('The quick brown fox jumps over the lazy dog'))).toBe(0x414fa339);
    expect(crc32(Uint8Array.from({ length: 256 }, (_, i) => i))).toBe(0x29058c73);
    expect(crc32(new Uint8Array())).toBe(0);
  });

  it('has the ISO-HDLC wire residue for varied messages', () => {
    for (const message of ['', '123456789', 'PAY $0010 TO ALICE']) {
      const bytes = enc.encode(message);
      expect(crc32(join(bytes, u32le(crc32(bytes))))).toBe(0x2144df1c);
    }
  });

  it('reverses every table index for varied upper register bits', () => {
    for (let low = 0; low < 256; low += 1) {
      const register = (Math.imul(low, 0x01010101) ^ 0xa5c37e00) >>> 0;
      const byte = 0;
      expect(crc32ReverseStep(crc32Step(register, byte), byte)).toBe(register);
    }
  });

  it('repairs equal-length changes and forces arbitrary targets through the genuine receiver', () => {
    let seed = 0x12345678;
    const next = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; };
    for (let trial = 0; trial < 200; trial += 1) {
      const a = Uint8Array.from({ length: trial % 67 }, () => next() & 255);
      const b = Uint8Array.from(a, (byte) => byte ^ (next() & 255));
      const sent = repairCrc(a, b, crc32(a));
      expect(sent).toBe(crc32(b));
      expect(crcReceiverAccepts(b, sent)).toBe(true);
      const target = next();
      const patched = forceCrc(a, target);
      expect(patched.length).toBe(a.length + 4);
      expect(crcReceiverAccepts(patched, target)).toBe(true);
    }
    expect(() => repairCrc(enc.encode('a'), enc.encode('bb'), 0)).toThrow(/equal/);
  });

  it('catches every single bit and every contiguous burst up to 32 bits', () => {
    const message = Uint8Array.from({ length: 64 }, (_, i) => i);
    const sent = crc32(message);
    for (let start = 0; start < message.length * 8; start += 1) {
      for (let length = 1; length <= Math.min(32, message.length * 8 - start); length += 1) {
        const altered = message.slice();
        for (let bit = start; bit < start + length; bit += 1) altered[bit >>> 3]! ^= 1 << (bit & 7);
        expect(crcReceiverAccepts(altered, sent)).toBe(false);
      }
    }
  });
});

it('HMAC byte verifier accepts a genuine tag and rejects the changed bytes', async () => {
  const receiver = await createHmacReceiver();
  const original = enc.encode('PAY $0010 TO ALICE');
  const tag = await receiver.sign(original);
  expect(await receiver.verify(original, tag)).toBe(true);
  expect(await receiver.verify(enc.encode('PAY $9000 TO ALICE'), tag)).toBe(false);
  const leakedKey = await crypto.subtle.importKey('raw', receiver.leakKeyForDemo(), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const forged = new Uint8Array(await crypto.subtle.sign('HMAC', leakedKey, enc.encode('PAY $9000 TO ALICE')));
  expect(await receiver.verify(enc.encode('PAY $9000 TO ALICE'), forged)).toBe(true);
  const key = await crypto.subtle.importKey('raw', enc.encode('cross-check-key'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const known = await computeHmac('ASCII message', 'cross-check-key', 'SHA-256');
  const knownTag = Uint8Array.from(known.macHex.match(/../g)!, (pair) => parseInt(pair, 16));
  expect(await crypto.subtle.verify('HMAC', key, knownTag, enc.encode('ASCII message'))).toBe(true);
  expect(readFileSync(new URL('./forge.ts', import.meta.url), 'utf8')).not.toMatch(/hmac-receiver|secret|CryptoKey/);
});
