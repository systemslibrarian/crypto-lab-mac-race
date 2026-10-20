import { checkBlocks, xor } from './cbcmac';
/** Attacker functions see only public messages/tags, never a key or MAC oracle. */
export function spliceOne(m: Uint8Array, t: Uint8Array): Uint8Array {
  if (m.length !== 16) throw new Error('The one-query example needs exactly one 16-byte message block.');
  const forged = new Uint8Array(32); forged.set(m); forged.set(xor(m, t), 16); return forged;
}
export function spliceTwo(m: Uint8Array, t: Uint8Array, mPrime: Uint8Array): Uint8Array {
  checkBlocks(m); checkBlocks(mPrime);
  const forged = new Uint8Array(m.length + mPrime.length); forged.set(m); forged.set(mPrime, m.length);
  forged.set(xor(mPrime.slice(0, 16), t), m.length); return forged;
}
