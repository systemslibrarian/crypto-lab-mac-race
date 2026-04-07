const encoder = new TextEncoder();

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

type State = Uint32Array;

export type LengthExtensionDemo = {
  originalMessage: string;
  appendMessage: string;
  originalMacHex: string;
  forgedMacHex: string;
  forgedMessageHex: string;
  verificationMacHex: string;
  valid: boolean;
  guessedSecretLength: number;
};

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

function ch(x: number, y: number, z: number): number {
  return (x & y) ^ (~x & z);
}

function maj(x: number, y: number, z: number): number {
  return (x & y) ^ (x & z) ^ (y & z);
}

function bigSigma0(x: number): number {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

function bigSigma1(x: number): number {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

function smallSigma0(x: number): number {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
}

function smallSigma1(x: number): number {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Expected hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function sha256Pad(totalLenBytes: number): Uint8Array {
  const bitLen = BigInt(totalLenBytes) * 8n;
  const mod = (totalLenBytes + 1) % 64;
  const zeroPad = mod <= 56 ? 56 - mod : 56 + (64 - mod);
  const out = new Uint8Array(1 + zeroPad + 8);
  out[0] = 0x80;
  for (let i = 0; i < 8; i += 1) {
    out[out.length - 1 - i] = Number((bitLen >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

function parseStateFromDigest(digestHex: string): State {
  const bytes = fromHex(digestHex);
  if (bytes.length !== 32) throw new Error('SHA-256 digest must be 32 bytes');
  const state = new Uint32Array(8);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < 8; i += 1) {
    state[i] = view.getUint32(i * 4, false);
  }
  return state;
}

function stateToDigestHex(state: State): string {
  const out = new Uint8Array(32);
  const view = new DataView(out.buffer);
  for (let i = 0; i < 8; i += 1) view.setUint32(i * 4, state[i], false);
  return toHex(out);
}

function compress(state: State, block: Uint8Array): void {
  const w = new Uint32Array(64);
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);

  for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(i * 4, false);
  for (let i = 16; i < 64; i += 1) {
    w[i] = (smallSigma1(w[i - 2]) + w[i - 7] + smallSigma0(w[i - 15]) + w[i - 16]) >>> 0;
  }

  let [a, b, c, d, e, f, g, h] = state;
  for (let i = 0; i < 64; i += 1) {
    const t1 = (h + bigSigma1(e) + ch(e, f, g) + K[i] + w[i]) >>> 0;
    const t2 = (bigSigma0(a) + maj(a, b, c)) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) >>> 0;
  }

  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
  state[5] = (state[5] + f) >>> 0;
  state[6] = (state[6] + g) >>> 0;
  state[7] = (state[7] + h) >>> 0;
}

function resumeSha256FromDigest(digestHex: string, processedBytes: number, toAppend: Uint8Array): string {
  const state = parseStateFromDigest(digestHex);
  const totalAfterAppend = processedBytes + toAppend.length;
  const finalInput = new Uint8Array(toAppend.length + sha256Pad(totalAfterAppend).length);
  finalInput.set(toAppend, 0);
  finalInput.set(sha256Pad(totalAfterAppend), toAppend.length);

  for (let i = 0; i < finalInput.length; i += 64) {
    compress(state, finalInput.slice(i, i + 64));
  }

  return stateToDigestHex(state);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return toHex(new Uint8Array(digest));
}

export async function runLengthExtensionDemo(message: string, appendText: string, secretLength = 16): Promise<LengthExtensionDemo> {
  const secret = crypto.getRandomValues(new Uint8Array(secretLength));
  const m = encoder.encode(message);
  const append = encoder.encode(appendText);

  const original = await sha256Hex(concat(secret, m));

  const glue = sha256Pad(secret.length + m.length);
  const forgedMessage = concat(concat(m, glue), append);

  const processedBeforeAppend = secret.length + m.length + glue.length;
  const forgedMac = resumeSha256FromDigest(original, processedBeforeAppend, append);

  const verification = await sha256Hex(concat(secret, forgedMessage));

  return {
    originalMessage: message,
    appendMessage: appendText,
    originalMacHex: original,
    forgedMacHex: forgedMac,
    forgedMessageHex: toHex(forgedMessage),
    verificationMacHex: verification,
    valid: forgedMac === verification,
    guessedSecretLength: secretLength
  };
}

export async function runLengthExtensionSelfTest(): Promise<boolean> {
  const demo = await runLengthExtensionDemo('comment=10&uid=7', '&admin=true', 16);
  return demo.valid;
}
