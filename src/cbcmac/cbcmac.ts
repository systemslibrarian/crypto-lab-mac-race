import { aesBlockEncrypt } from './aesBlock';
export const NOT_BLOCK_ALIGNED = 'NOT_BLOCK_ALIGNED';
export const LENGTH_MISMATCH = 'LENGTH_MISMATCH';
export const TAG_MISMATCH = 'TAG_MISMATCH';
export const EMPTY_MESSAGE = 'EMPTY_MESSAGE';
export class MacInputError extends Error { constructor(public code: string, message: string) { super(`${code}: ${message}`); } }
export type ChainStep = { block: Uint8Array; chainIn: Uint8Array; aesInput: Uint8Array; output: Uint8Array };
export type Verification = { accepted: boolean; code: string; expected?: Uint8Array; steps?: ChainStep[] };
export const hex = (bytes: Uint8Array): string => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export const unhex = (value: string): Uint8Array => { if (!/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error('Expected whole hex bytes'); return Uint8Array.from(value.match(/../g) ?? [], b => Number.parseInt(b, 16)); };
export function checkBlocks(message: Uint8Array): void {
  if (!message.length) throw new MacInputError(EMPTY_MESSAGE, 'Raw CBC-MAC refuses an empty message: with no blocks the tag would just be the IV.');
  if (message.length % 16) throw new MacInputError(NOT_BLOCK_ALIGNED, `Received ${message.length} bytes; next valid length is ${Math.ceil(message.length / 16) * 16} bytes. No padding is added.`);
}
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array { if (a.length !== 16 || b.length !== 16) throw new Error('XOR needs two 16-byte blocks'); return Uint8Array.from(a, (x, i) => x ^ b[i]!); }
export function equalTag(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
export async function rawCbcMacTrace(key: Uint8Array, message: Uint8Array): Promise<{ tag: Uint8Array; steps: ChainStep[] }> {
  key = new Uint8Array(key); message = new Uint8Array(message); checkBlocks(message);
  let chain: Uint8Array = new Uint8Array(16); const steps: ChainStep[] = [];
  for (let i = 0; i < message.length; i += 16) {
    const block = message.slice(i, i + 16), chainIn = new Uint8Array(chain), aesInput = xor(chainIn, block);
    chain = await aesBlockEncrypt(key, aesInput);
    steps.push({ block, chainIn, aesInput, output: new Uint8Array(chain) });
  }
  return { tag: chain, steps };
}
export async function rawCbcMac(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> { return (await rawCbcMacTrace(key, message)).tag; }
/** Message BYTE length, encoded as one unsigned 128-bit big-endian block. */
export function lengthBlock(bytes: number): Uint8Array {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error('Length must be a nonnegative safe integer');
  let value = BigInt(bytes); const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) { out[i] = Number(value & 255n); value >>= 8n; }
  return out;
}
export async function prependLengthCbcMac(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  checkBlocks(message); const framed = new Uint8Array(message.length + 16);
  framed.set(lengthBlock(message.length)); framed.set(message, 16);
  // [extension] Length-appending and ECBC need separate constructions and demonstrations.
  return rawCbcMac(key, framed);
}
async function verifyRaw(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<Verification> {
  try { const result = await rawCbcMacTrace(key, message), accepted = equalTag(result.tag, tag); return { accepted, code: accepted ? 'OK' : TAG_MISMATCH, expected: result.tag, steps: result.steps }; }
  catch (error) { if (error instanceof MacInputError) return { accepted: false, code: error.code }; throw error; }
}
export async function verifyAnyLength(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<Verification> {
  return verifyRaw(key, message, tag);
}
export async function verifyFixedLength(key: Uint8Array, message: Uint8Array, tag: Uint8Array, agreedBytes: number): Promise<Verification> {
  if (!Number.isInteger(agreedBytes) || agreedBytes <= 0 || agreedBytes % 16) throw new Error('Agreed length must be a positive whole number of blocks');
  if (message.length !== agreedBytes) return { accepted: false, code: LENGTH_MISMATCH };
  return verifyRaw(key, message, tag);
}
export async function verifyPrepended(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<Verification> {
  try { const expected = await prependLengthCbcMac(key, message), accepted = equalTag(expected, tag); return { accepted, code: accepted ? 'OK' : TAG_MISMATCH, expected }; }
  catch (error) { if (error instanceof MacInputError) return { accepted: false, code: error.code }; throw error; }
}
