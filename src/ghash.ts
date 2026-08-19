import { bytesToHex, hexToBytes } from '@noble/ciphers/utils.js';

const BLOCK_SIZE = 16;
const R = 0xe1000000000000000000000000000000n;
const MOD128 = (1n << 128n) - 1n;

export type GhashResult = {
  hHex: string;
  yHex: string;
  steps: string[];
};

export type GhashReuseDemo = {
  c1Hex: string;
  c2Hex: string;
  t1Hex: string;
  t2Hex: string;
  deltaCHex: string;
  deltaTHex: string;
  recoveredHHex: string;
  hMatchesTrue: boolean;
  targetCiphertextHex: string;
  forgedTagHex: string;
  serverAccepts: boolean;
  forgedValid: boolean;
  note: string;
};

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i += 1) out[i] = a[i] ^ b[i];
  return out;
}

function toBigIntBE(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) + BigInt(b);
  return out;
}

function fromBigIntBE(n: bigint): Uint8Array {
  const out = new Uint8Array(BLOCK_SIZE);
  let x = n & MOD128;
  for (let i = BLOCK_SIZE - 1; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function gf128Mul(xBytes: Uint8Array, yBytes: Uint8Array): Uint8Array {
  const x = toBigIntBE(xBytes);
  let y = toBigIntBE(yBytes);
  let z = 0n;

  for (let i = 0; i < 128; i += 1) {
    if ((x & (1n << BigInt(127 - i))) !== 0n) {
      z ^= y;
    }
    const lsb = y & 1n;
    y >>= 1n;
    if (lsb) y ^= R;
  }

  return fromBigIntBE(z);
}

function toBlockLength(aadLenBytes: number, cLenBytes: number): Uint8Array {
  const out = new Uint8Array(BLOCK_SIZE);
  const aadBits = BigInt(aadLenBytes) * 8n;
  const cBits = BigInt(cLenBytes) * 8n;
  for (let i = 0; i < 8; i += 1) {
    out[7 - i] = Number((aadBits >> BigInt(i * 8)) & 0xffn);
    out[15 - i] = Number((cBits >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

function chunk16(data: Uint8Array): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += BLOCK_SIZE) {
    const block = new Uint8Array(BLOCK_SIZE);
    block.set(data.slice(i, i + BLOCK_SIZE), 0);
    blocks.push(block);
  }
  if (data.length === 0) blocks.push(new Uint8Array(BLOCK_SIZE));
  return blocks;
}

async function aesEncryptBlockWebCrypto(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
  const iv = new Uint8Array(BLOCK_SIZE);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, cryptoKey, block as BufferSource);
  return new Uint8Array(encrypted).slice(0, BLOCK_SIZE);
}

export async function computeGhash(ciphertextHex: string, keyHex?: string): Promise<GhashResult> {
  const c = hexToBytes(ciphertextHex);
  const key = keyHex ? hexToBytes(keyHex) : crypto.getRandomValues(new Uint8Array(16));
  const h = await aesEncryptBlockWebCrypto(key, new Uint8Array(BLOCK_SIZE));

  let y: Uint8Array = new Uint8Array(BLOCK_SIZE);
  const steps: string[] = [];

  for (const block of chunk16(c)) {
    y = gf128Mul(xor16(y, block), h);
    steps.push(bytesToHex(y));
  }

  const lengthBlock = toBlockLength(0, c.length);
  y = gf128Mul(xor16(y, lengthBlock), h);
  steps.push(bytesToHex(y));

  return {
    hHex: bytesToHex(h),
    yHex: bytesToHex(y),
    steps
  };
}

function gfPow2(x: Uint8Array): Uint8Array {
  return gf128Mul(x, x);
}

function gfInv(x: Uint8Array): Uint8Array {
  let exp = (1n << 128n) - 2n;
  let base: Uint8Array = x;
  let result: Uint8Array = new Uint8Array(BLOCK_SIZE);
  result[0] = 0x80;

  while (exp > 0n) {
    if ((exp & 1n) === 1n) result = gf128Mul(result, base);
    base = gfPow2(base);
    exp >>= 1n;
  }
  return result;
}

/**
 * Live Forbidden Attack. Nothing here is hard-coded: we generate a fresh AES
 * key each run, derive the real hash subkey H = E_K(0^128) via WebCrypto, and
 * pick two random single-block ciphertexts. Reusing the same nonce means both
 * are authenticated with the same H, so the attacker sees
 *   T1 = C1 · H,   T2 = C2 · H   (single-block GHASH, no length block).
 * Because GHASH is linear over GF(2^128):
 *   ΔT = T1 ⊕ T2 = (C1 ⊕ C2) · H = ΔC · H,   so   H = ΔT · ΔC⁻¹.
 * We then forge a tag for a fresh target ciphertext and the "server" (which
 * still holds the true H) independently confirms the forgery is accepted.
 */
export async function runGhashReuseAttackDemo(): Promise<GhashReuseDemo> {
  const key = crypto.getRandomValues(new Uint8Array(16));
  const h = await aesEncryptBlockWebCrypto(key, new Uint8Array(BLOCK_SIZE));

  const c1 = crypto.getRandomValues(new Uint8Array(BLOCK_SIZE));
  const c2 = crypto.getRandomValues(new Uint8Array(BLOCK_SIZE));

  // Observed authentication tags for the two nonce-reusing messages.
  const t1 = gf128Mul(c1, h);
  const t2 = gf128Mul(c2, h);

  // Attacker's algebra — recover H from the two observations alone.
  const deltaC = xor16(c1, c2);
  const deltaT = xor16(t1, t2);
  const recoveredH = gf128Mul(deltaT, gfInv(deltaC));

  // Forge a tag for a brand-new ciphertext using only the recovered H.
  const target = crypto.getRandomValues(new Uint8Array(BLOCK_SIZE));
  const forgedTag = gf128Mul(target, recoveredH);

  // The server still holds the *true* H and computes the genuine tag; if the
  // forgery matches, the attack is verified end-to-end (not self-graded).
  const genuineTag = gf128Mul(target, h);
  const serverAccepts = ctEq16(forgedTag, genuineTag);

  return {
    c1Hex: bytesToHex(c1),
    c2Hex: bytesToHex(c2),
    t1Hex: bytesToHex(t1),
    t2Hex: bytesToHex(t2),
    deltaCHex: bytesToHex(deltaC),
    deltaTHex: bytesToHex(deltaT),
    recoveredHHex: bytesToHex(recoveredH),
    hMatchesTrue: ctEq16(recoveredH, h),
    targetCiphertextHex: bytesToHex(target),
    forgedTagHex: bytesToHex(forgedTag),
    serverAccepts,
    forgedValid: serverAccepts,
    note: 'H was derived live from a fresh AES key; nonce reuse gives ΔT = ΔC·H, so H = ΔT·ΔC⁻¹ and forgeries follow for any ciphertext.'
  };
}

function ctEq16(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function verifyGhash(ciphertextHex: string, keyHex: string, candidateTagHex: string): Promise<boolean> {
  try {
    const expected = await computeGhash(ciphertextHex, keyHex);
    const a = expected.yHex.toLowerCase();
    const b = candidateTagHex.trim().toLowerCase();
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  } catch {
    return false;
  }
}

export function runGhashSelfTest(): boolean {
  const h = hexToBytes('66e94bd4ef8a2c3b884cfa59ca342b2e');
  const x = hexToBytes('0388dace60b6a392f328c2b971b2fe78');
  const expected = '5e2ec746917062882c85b0685353deb7';
  return bytesToHex(gf128Mul(x, h)) === expected;
}
