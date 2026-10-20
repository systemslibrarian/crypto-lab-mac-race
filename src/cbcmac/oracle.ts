import { cmacBytes } from '../cmac';
import { checkBlocks, equalTag, LENGTH_MISMATCH, MacInputError, prependLengthCbcMac, rawCbcMac, TAG_MISMATCH, unhex, verifyAnyLength, verifyFixedLength, verifyPrepended, type Verification } from './cbcmac';
export type Variant = 'raw' | 'fixed' | 'prepended' | 'cmac';
export type MacOracle = { mac(message: Uint8Array): Promise<Uint8Array>; verify(message: Uint8Array, tag: Uint8Array): Promise<Verification> };
function withKey(key: Uint8Array, variant: Variant, agreedLength: () => number): MacOracle {
  return Object.freeze({
    async mac(message: Uint8Array) {
      message = new Uint8Array(message); checkBlocks(message);
      if (variant === 'fixed' && message.length !== agreedLength()) throw new MacInputError(LENGTH_MISMATCH, 'Sender and receiver must agree on the same message length.');
      if (variant === 'cmac') return unhex((await cmacBytes(key, message)).tagHex);
      return variant === 'prepended' ? prependLengthCbcMac(key, message) : rawCbcMac(key, message);
    },
    async verify(message: Uint8Array, tag: Uint8Array) {
      message = new Uint8Array(message); tag = new Uint8Array(tag);
      if (variant === 'fixed') return verifyFixedLength(key, message, tag, agreedLength());
      if (variant === 'raw') return verifyAnyLength(key, message, tag);
      if (variant === 'prepended') return verifyPrepended(key, message, tag);
      const expected = unhex((await cmacBytes(key, message)).tagHex), accepted = equalTag(expected, tag);
      return { accepted, code: accepted ? 'OK' : TAG_MISMATCH, expected };
    }
  });
}
export function makeMacOracle(variant: Variant, agreedLength = () => 16): MacOracle {
  return withKey(crypto.getRandomValues(new Uint8Array(32)), variant, agreedLength);
}
/** Raw and fixed-length receivers share a key so length is the only difference.
 * Prepended and CMAC are independent scheme experiments with separate keys.
 * Sharing CMAC's key with a raw-CBC-MAC signing oracle would permit a different
 * cross-protocol attack (pinned independently in tests). Only mac/verify cross
 * the boundary. Verifier traces are displayed after submission, not forge inputs. */
export function makeLessonOracles(agreedLength: () => number): Record<Variant, MacOracle> {
  const key = crypto.getRandomValues(new Uint8Array(32));
  return { raw: withKey(key, 'raw', agreedLength), fixed: withKey(key, 'fixed', agreedLength), prepended: makeMacOracle('prepended'), cmac: makeMacOracle('cmac') };
}
