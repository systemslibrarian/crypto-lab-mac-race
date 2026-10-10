import { poly1305 } from '@noble/ciphers/_poly1305.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const P130 = (1n << 130n) - 5n;
const MOD128 = 1n << 128n;

export type Poly1305Result = {
  tagHex: string;
  keyHex: string;
  notes: string;
};

export type Poly1305ReuseDemo = {
  msg1: string;
  msg2: string;
  msg3: string;
  tag1Hex: string;
  tag2Hex: string;
  forgedTagHex: string;
  validForgery: boolean;
  recoveredRHex: string;
  /**
   * Bits of `r` that the classroom demo leaves free to brute-force. Real
   * Poly1305 `r` is a ~106-bit clamped value. This narrowing is a choice for
   * simple classroom brute force, not a claim that full-size one-block reuse
   * is intractable. With known single-block messages, the large pre-reduction
   * quotient disappears modulo 2^130-5; final tag truncation leaves a small
   * number of carry candidates. An additional observation may disambiguate
   * candidates. Two tags do not universally identify one key, and arbitrary
   * multi-block messages have different polynomial equations (RFC 8439 §2.5).
   */
  rSpaceBits: number;
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Expected an even-length hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function leBytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    n = (n << 8n) + BigInt(bytes[i]);
  }
  return n;
}

function bigIntToLe(n: bigint, length: number): Uint8Array {
  let x = n;
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function oneBlockToBigInt(message: Uint8Array): bigint {
  const block = new Uint8Array(17);
  block.set(message, 0);
  block[message.length] = 1;
  return leBytesToBigInt(block);
}

function polyOneBlockAcc(message: Uint8Array, r: bigint): bigint {
  const m = oneBlockToBigInt(message);
  return (m * r) % P130;
}

// Bits of `r` left free for simple classroom brute force. For the particular
// 14-byte invoice messages below, r < 2^16 also keeps m·r below 2^130-5.
// This is not a bound on full-size key-reuse attacks; see rSpaceBits above.
export const DEMO_R_SPACE_BITS = 16;

// Builds a one-time key whose `r` lives in a `DEMO_R_SPACE_BITS`-bit window.
// The `s` half stays fully random; only `r` is constrained. This is a teaching
// simplification and is disclosed in the UI — it is NOT how real Poly1305 keys
// are generated (RFC 8439 derives a full 256-bit unpredictable key per message).
function deriveTeachingReuseKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  // Zero all r-bytes above the low 16 bits (r occupies key[0..15], LE).
  key[2] = 0;
  key[3] = 0;
  for (let i = 4; i < 16; i += 1) key[i] = 0;
  return key;
}

export function constantTimeEqual16(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function computePoly1305(message: string, keyHex?: string): Poly1305Result {
  const msg = encoder.encode(message);
  // The compute panel uses a full 256-bit random one-time key, as RFC 8439
  // requires. (The reuse *attack* panel deliberately uses a constrained key —
  // see deriveTeachingReuseKey — but that must not leak into normal tag output.)
  const key = keyHex ? fromHex(keyHex) : crypto.getRandomValues(new Uint8Array(32));
  if (key.length !== 32) {
    throw new Error('Poly1305 key must be exactly 32 bytes (64 hex chars)');
  }
  const tag = poly1305(msg, key);
  return {
    tagHex: toHex(tag),
    keyHex: toHex(key),
    notes: 'Poly1305 key is one-time only. Reusing it breaks authenticity guarantees.'
  };
}

export function runKeyReuseAttackDemo(): Poly1305ReuseDemo {
  const key = deriveTeachingReuseKey();
  const msg1 = encoder.encode('Invoice=1000USD');
  const msg2 = encoder.encode('Invoice=9000USD');
  const msg3 = encoder.encode('Invoice=9999USD');

  const tag1 = poly1305(msg1, key);
  const tag2 = poly1305(msg2, key);

  const tag1Int = leBytesToBigInt(tag1);
  const tag2Int = leBytesToBigInt(tag2);

  let recoveredR = -1n;
  let recoveredS = 0n;

  for (let rGuess = 0n; rGuess <= 0xffffn; rGuess += 1n) {
    const acc1 = polyOneBlockAcc(msg1, rGuess);
    const sGuess = ((tag1Int - acc1) % MOD128 + MOD128) % MOD128;
    const acc2 = polyOneBlockAcc(msg2, rGuess);
    const predicted2 = (acc2 + sGuess) % MOD128;
    if (predicted2 === tag2Int) {
      recoveredR = rGuess;
      recoveredS = sGuess;
      break;
    }
  }

  if (recoveredR < 0n) {
    throw new Error('Failed to recover weak Poly1305 key; retry demo');
  }

  const acc3 = polyOneBlockAcc(msg3, recoveredR);
  const forged = (acc3 + recoveredS) % MOD128;
  const forgedTag = bigIntToLe(forged, 16);
  const realTag = poly1305(msg3, key);

  return {
    msg1: decoder.decode(msg1),
    msg2: decoder.decode(msg2),
    msg3: decoder.decode(msg3),
    tag1Hex: toHex(tag1),
    tag2Hex: toHex(tag2),
    forgedTagHex: toHex(forgedTag),
    validForgery: constantTimeEqual16(forgedTag, realTag),
    recoveredRHex: recoveredR.toString(16).padStart(4, '0'),
    rSpaceBits: DEMO_R_SPACE_BITS
  };
}

export function verifyPoly1305(message: string, keyHex: string, candidateTagHex: string): boolean {
  try {
    const msg = encoder.encode(message);
    const key = fromHex(keyHex);
    if (key.length !== 32) return false;
    const expected = poly1305(msg, key);
    const candidate = fromHex(candidateTagHex);
    return constantTimeEqual16(expected, candidate);
  } catch {
    return false;
  }
}

export function runPoly1305SelfTest(): boolean {
  const key = fromHex('85d6be7857556d337f4452fe42d506a8' + '0103808afb0db2fd4abff6af4149f51b');
  const msg = encoder.encode('Cryptographic Forum Research Group');
  const expected = 'a8061dc1305136c6c22b8baf0c0127a9';
  const tag = poly1305(msg, key);
  return toHex(tag) === expected;
}
