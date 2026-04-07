import { poly1305 } from '@noble/ciphers/_poly1305';

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

function deriveWeakOneTimeKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
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
  const key = keyHex ? fromHex(keyHex) : deriveWeakOneTimeKey();
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
  const key = deriveWeakOneTimeKey();
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
    const sGuess = (tag1Int - acc1 + MOD128) % MOD128;
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
    recoveredRHex: recoveredR.toString(16).padStart(4, '0')
  };
}

export function runPoly1305SelfTest(): boolean {
  const key = fromHex('85d6be7857556d337f4452fe42d506a8' + '0103808afb0db2fd4abff6af4149f51b');
  const msg = encoder.encode('Cryptographic Forum Research Group');
  const expected = 'a8061dc1305136c6c22b8baf0c0127a9';
  const tag = poly1305(msg, key);
  return toHex(tag) === expected;
}
