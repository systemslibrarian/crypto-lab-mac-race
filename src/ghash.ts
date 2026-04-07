import { bytesToHex, hexToBytes } from '@noble/ciphers/utils';

const BLOCK_SIZE = 16;
const R = 0xe1000000000000000000000000000000n;
const MOD128 = (1n << 128n) - 1n;

export type GhashResult = {
  hHex: string;
  yHex: string;
  steps: string[];
};

export type GhashReuseDemo = {
  deltaCHex: string;
  deltaTHex: string;
  recoveredHHex: string;
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

function gf128Mul(xBytes: Uint8Array, yBytes: Uint8Array): Uint8Array {
  let x = toBigIntBE(xBytes);
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

  let y: Uint8Array<ArrayBufferLike> = new Uint8Array(BLOCK_SIZE);
  const steps: string[] = [];

  for (const block of chunk16(c)) {
    y = gf128Mul(xor16(y as any, block as any), h as any) as any;
    steps.push(bytesToHex(y));
  }

  const lengthBlock = toBlockLength(0, c.length);
  y = gf128Mul(xor16(y as any, lengthBlock as any), h as any) as any;
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
  let base: Uint8Array<ArrayBufferLike> = x;
  let result: Uint8Array<ArrayBufferLike> = new Uint8Array(BLOCK_SIZE);
  result[15] = 1;

  while (exp > 0n) {
    if ((exp & 1n) === 1n) result = gf128Mul(result as any, base as any) as any;
    base = gfPow2(base);
    exp >>= 1n;
  }
  return result;
}

export function runGhashReuseAttackDemo(): GhashReuseDemo {
  const h = hexToBytes('66e94bd4ef8a2c3b884cfa59ca342b2e');
  const c1 = hexToBytes('0388dace60b6a392f328c2b971b2fe78');
  const c2 = hexToBytes('42831ec2217774244b7221b784d0d49c');

  const t1 = gf128Mul(c1, h);
  const t2 = gf128Mul(c2, h);

  const deltaC = xor16(c1, c2);
  const deltaT = xor16(t1, t2);

  const recoveredH = gf128Mul(deltaT, gfInv(deltaC));

  const c3 = hexToBytes('feedfacedeadbeeffeedfacedeadbeef');
  const forgedTag = gf128Mul(c3, recoveredH);
  const realTag = gf128Mul(c3, h);

  return {
    deltaCHex: bytesToHex(deltaC),
    deltaTHex: bytesToHex(deltaT),
    recoveredHHex: bytesToHex(recoveredH),
    forgedValid: bytesToHex(forgedTag) === bytesToHex(realTag),
    note: 'Nonce reuse leaks linear equations in GHASH; with enough structure, H can be solved and forgeries follow.'
  };
}

export function runGhashSelfTest(): boolean {
  const h = hexToBytes('66e94bd4ef8a2c3b884cfa59ca342b2e');
  const x = hexToBytes('0388dace60b6a392f328c2b971b2fe78');
  const expected = '5e2ec746917062882c85b0685353deb7';
  return bytesToHex(gf128Mul(x, h)) === expected;
}
