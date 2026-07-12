import { resumeSha256FromDigest, sha256Pad } from './sha256core';

const encoder = new TextEncoder();

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

export type ForgeAttempt = {
  guessedSecretLength: number;
  actualSecretLength: number;
  forgedMessageHex: string;
  forgedMessageVisible: string;
  forgedRawTagHex: string;
  forgedHmacTagAttemptHex: string;
  rawServerAccepts: boolean;
  hmacServerAccepts: boolean;
  guessCorrect: boolean;
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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

async function hmacSha256Hex(key: Uint8Array, data: Uint8Array): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data as BufferSource);
  return toHex(new Uint8Array(sig));
}

// A persistent demo secret. The "attacker" (user) does not see this.
// Length is randomized within a range so the slider game is meaningful.
let demoSecret: Uint8Array = generateSecret();

function generateSecret(): Uint8Array {
  const length = 8 + Math.floor(Math.random() * 17); // 8..24 inclusive
  return crypto.getRandomValues(new Uint8Array(length));
}

export function regenerateDemoSecret(): number {
  demoSecret = generateSecret();
  return demoSecret.length;
}

export function getActualSecretLength(): number {
  return demoSecret.length;
}

export const ATTACKER_SECRET_LENGTH_RANGE: [number, number] = [8, 24];

export async function captureOriginalRequest(message: string): Promise<{
  rawMacHex: string;
  hmacMacHex: string;
}> {
  const m = encoder.encode(message);
  const rawMacHex = await sha256Hex(concat(demoSecret, m));
  const hmacMacHex = await hmacSha256Hex(demoSecret, m);
  return { rawMacHex, hmacMacHex };
}

// Server endpoints. The "raw" server uses the broken construction
// SHA-256(secret || message), which is vulnerable to length-extension.
// The "hmac" server uses HMAC-SHA-256(secret, message), which is not.
export async function rawServerVerify(messageBytes: Uint8Array, candidateMacHex: string): Promise<boolean> {
  const expected = await sha256Hex(concat(demoSecret, messageBytes));
  return ctEqHex(expected, candidateMacHex);
}

export async function hmacServerVerify(messageBytes: Uint8Array, candidateMacHex: string): Promise<boolean> {
  const expected = await hmacSha256Hex(demoSecret, messageBytes);
  return ctEqHex(expected, candidateMacHex);
}

function ctEqHex(aHex: string, bHex: string): boolean {
  const a = aHex.toLowerCase();
  const b = bHex.trim().toLowerCase();
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// User-driven forging: the attacker picks a guessed secret length and an
// "&admin=true"-style append. We compute the forged tag/message and submit
// both forgeries to the two server endpoints.
export async function attemptForge(
  originalMessage: string,
  originalRawMacHex: string,
  originalHmacMacHex: string,
  appendText: string,
  guessedSecretLength: number
): Promise<ForgeAttempt> {
  const m = encoder.encode(originalMessage);
  const append = encoder.encode(appendText);

  const glue = sha256Pad(guessedSecretLength + m.length);
  const forgedSuffix = concat(concat(m, glue), append);

  const processedBefore = guessedSecretLength + m.length + glue.length;
  const forgedRawTag = resumeSha256FromDigest(originalRawMacHex, processedBefore, append);
  // Apply the same length-extension technique against the HMAC tag.
  // This is mathematically doomed because HMAC's outer hash wraps the
  // inner state — the attacker cannot resume from the outer digest in a
  // way that the server will accept. We compute it anyway to show the
  // failure side-by-side.
  const forgedHmacAttempt = resumeSha256FromDigest(originalHmacMacHex, processedBefore, append);

  const rawAccepts = await rawServerVerify(forgedSuffix, forgedRawTag);
  const hmacAccepts = await hmacServerVerify(forgedSuffix, forgedHmacAttempt);

  return {
    guessedSecretLength,
    actualSecretLength: demoSecret.length,
    forgedMessageHex: toHex(forgedSuffix),
    forgedMessageVisible: decodeVisible(forgedSuffix),
    forgedRawTagHex: forgedRawTag,
    forgedHmacTagAttemptHex: forgedHmacAttempt,
    rawServerAccepts: rawAccepts,
    hmacServerAccepts: hmacAccepts,
    guessCorrect: guessedSecretLength === demoSecret.length
  };
}

function decodeVisible(bytes: Uint8Array): string {
  // Render printable ASCII as-is, others as \xNN, so the user can see the
  // glue padding visually inside the forged message.
  let out = '';
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
    else out += `\\x${b.toString(16).padStart(2, '0')}`;
  }
  return out;
}

// Legacy entry point kept for self-test compatibility.
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
