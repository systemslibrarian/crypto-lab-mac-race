const encoder = new TextEncoder();

export type HmacAlgo = 'SHA-256' | 'SHA-512';

export type HmacVisual = {
  normalizedKeyHex: string;
  ipadHex: string;
  opadHex: string;
  innerHashHex: string;
  outerHashHex: string;
};

export type HmacResult = {
  macHex: string;
  visual: HmacVisual;
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

function parseKey(keyInput: string): Uint8Array {
  const trimmed = keyInput.trim();
  if (trimmed.length === 0) {
    throw new Error('Key must not be empty');
  }
  return isHex(trimmed) ? fromHex(trimmed) : encoder.encode(keyInput);
}

async function digest(hash: HmacAlgo, data: Uint8Array): Promise<Uint8Array> {
  const result = await crypto.subtle.digest(hash, data as BufferSource);
  return new Uint8Array(result);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function buildVisual(hash: HmacAlgo, keyBytes: Uint8Array, messageBytes: Uint8Array): Promise<HmacVisual> {
  const blockSize = hash === 'SHA-256' ? 64 : 128;
  const normalized = new Uint8Array(blockSize);
  const k0 = keyBytes.length > blockSize ? await digest(hash, keyBytes) : keyBytes;
  normalized.set(k0.slice(0, blockSize));

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i += 1) {
    ipad[i] = normalized[i] ^ 0x36;
    opad[i] = normalized[i] ^ 0x5c;
  }

  const innerHash = await digest(hash, concat(ipad, messageBytes));
  const outerHash = await digest(hash, concat(opad, innerHash));

  return {
    normalizedKeyHex: toHex(normalized),
    ipadHex: toHex(ipad),
    opadHex: toHex(opad),
    innerHashHex: toHex(innerHash),
    outerHashHex: toHex(outerHash)
  };
}

export async function computeHmac(message: string, key: string, hash: HmacAlgo): Promise<HmacResult> {
  const messageBytes = encoder.encode(message);
  const keyBytes = parseKey(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    {
      name: 'HMAC',
      hash
    },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
  const macHex = toHex(new Uint8Array(signature));
  const visual = await buildVisual(hash, keyBytes, messageBytes);

  return { macHex, visual };
}

export async function avalancheBitFlip(message: string, key: string): Promise<{
  original: string;
  flippedMessage: string;
  flippedKey: string;
}> {
  const messageBytes = encoder.encode(message || 'A');
  const keyBytes = parseKey(key || 'default-key');

  const messageFlip = new Uint8Array(messageBytes);
  messageFlip[0] ^= 0x01;

  const keyFlip = new Uint8Array(keyBytes);
  keyFlip[0] ^= 0x01;

  const base = await computeHmac(message || 'A', key || 'default-key', 'SHA-256');

  const msgKey = await crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const keyKey = await crypto.subtle.importKey(
    'raw',
    keyFlip as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const msgSig = await crypto.subtle.sign('HMAC', msgKey, messageFlip);
  const keySig = await crypto.subtle.sign('HMAC', keyKey, messageBytes);

  return {
    original: base.macHex,
    flippedMessage: toHex(new Uint8Array(msgSig)),
    flippedKey: toHex(new Uint8Array(keySig))
  };
}

export async function runHmacSelfTest(): Promise<boolean> {
  const key = new Uint8Array(20).fill(0x0b);
  const keyHex = toHex(key);
  const msg = 'Hi There';
  const expected256 = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';
  const expected512 = '87aa7cdea5ef619d4ff0b4241a1d6cb0' +
    '2379f4e2ce4ec2787ad0b30545e17cde' +
    'daa833b7d6b8a702038b274eaea3f4e4' +
    'be9d914eeb61f1702e696c203a126854';

  const h256 = await computeHmac(msg, keyHex, 'SHA-256');
  const h512 = await computeHmac(msg, keyHex, 'SHA-512');
  return h256.macHex === expected256 && h512.macHex === expected512;
}
