const encoder = new TextEncoder();
const BLOCK_SIZE = 16;
const RB = 0x87;

export type CmacDetails = {
  keyHex: string;
  k1Hex: string;
  k2Hex: string;
  paddedLastBlockHex: string;
  finalXorBlockHex: string;
  chainingHex: string[];
};

export type CmacResult = {
  tagHex: string;
  details: CmacDetails;
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

function isHex(input: string): boolean {
  return /^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0;
}

async function deriveAes256Key(input: string): Promise<Uint8Array> {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error('CMAC key is required');
  }
  if (isHex(trimmed) && trimmed.length === 64) {
    return fromHex(trimmed);
  }
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return new Uint8Array(digest);
}

function xorBlock(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function leftShiftBlock(block: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK_SIZE);
  let carry = 0;
  for (let i = BLOCK_SIZE - 1; i >= 0; i -= 1) {
    const byte = block[i];
    out[i] = ((byte << 1) & 0xff) | carry;
    carry = (byte & 0x80) >>> 7;
  }
  return out;
}

async function aesBlockEncrypt(keyBytes: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
  const iv = new Uint8Array(BLOCK_SIZE);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, block as BufferSource);
  return new Uint8Array(encrypted).slice(0, BLOCK_SIZE);
}

async function deriveSubkeys(keyBytes: Uint8Array): Promise<{ k1: Uint8Array; k2: Uint8Array }> {
  const zeroBlock = new Uint8Array(BLOCK_SIZE);
  const l = await aesBlockEncrypt(keyBytes, zeroBlock);

  let k1 = leftShiftBlock(l);
  if ((l[0] & 0x80) !== 0) {
    k1[BLOCK_SIZE - 1] ^= RB;
  }

  let k2 = leftShiftBlock(k1);
  if ((k1[0] & 0x80) !== 0) {
    k2[BLOCK_SIZE - 1] ^= RB;
  }

  return { k1, k2 };
}

function splitBlocks(message: Uint8Array): Uint8Array[] {
  if (message.length === 0) {
    return [new Uint8Array(BLOCK_SIZE)];
  }

  const blocks: Uint8Array[] = [];
  for (let i = 0; i < message.length; i += BLOCK_SIZE) {
    blocks.push(message.slice(i, i + BLOCK_SIZE));
  }
  return blocks;
}

function padBlock(block: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK_SIZE);
  out.set(block, 0);
  out[block.length] = 0x80;
  return out;
}

export async function computeCmac(message: string, keyInput: string): Promise<CmacResult> {
  return computeCmacBytes(encoder.encode(message), keyInput);
}

async function computeCmacBytes(messageBytes: Uint8Array, keyInput: string): Promise<CmacResult> {
  const keyBytes = await deriveAes256Key(keyInput);
  const { k1, k2 } = await deriveSubkeys(keyBytes);
  const blocks = splitBlocks(messageBytes);

  const lastIndex = blocks.length - 1;
  const complete = messageBytes.length !== 0 && messageBytes.length % BLOCK_SIZE === 0;
  const lastRaw = blocks[lastIndex];
  const paddedLastBlock = complete ? lastRaw : padBlock(lastRaw);
  const finalXorBlock = xorBlock(paddedLastBlock, complete ? k1 : k2);

  let c: Uint8Array<ArrayBufferLike> = new Uint8Array(BLOCK_SIZE);
  const chain: string[] = [];

  for (let i = 0; i < lastIndex; i += 1) {
    c = (await aesBlockEncrypt(keyBytes as any, xorBlock(c as any, blocks[i] as any) as any)) as any;
    chain.push(toHex(c));
  }

  const tag = await aesBlockEncrypt(keyBytes, xorBlock(c, finalXorBlock));

  return {
    tagHex: toHex(tag),
    details: {
      keyHex: toHex(keyBytes),
      k1Hex: toHex(k1),
      k2Hex: toHex(k2),
      paddedLastBlockHex: toHex(paddedLastBlock),
      finalXorBlockHex: toHex(finalXorBlock),
      chainingHex: chain
    }
  };
}

export async function runCmacSelfTest(): Promise<boolean> {
  const keyHex =
    '603deb1015ca71be2b73aef0857d7781' +
    '1f352c073b6108d72d9810a30914dff4';
  const messageHex = '6bc1bee22e409f96e93d7e117393172a';
  const expectedTag = '28a7023f452e8f82bd4bf28d8c37c35c';

  const key = fromHex(keyHex);
  const result = await computeCmacBytes(fromHex(messageHex), keyHex);

  return toHex(key) === result.details.keyHex && result.tagHex === expectedTag;
}
