/**
 * A uniform integer in [0, limit), drawn by rejection rather than by `% limit`.
 *
 * `crypto.getRandomValues(new Uint32Array(1))[0] % limit` makes the first
 * `2**32 % limit` values slightly likelier than the rest. CodeQL names it
 * js/biased-cryptographic-random. The CRC exhibit used that form to pick which
 * bits to corrupt, which is not key material -- but it is cheaper to remove the
 * bias than to argue about how small it is, and the exhibit's claim is that the
 * corruption is uniform over the message.
 *
 * Discarding the short tail above the largest multiple of `limit` costs one
 * extra draw with probability under `limit / 2**32`.
 */

/** The rejection bound: the largest multiple of `limit` inside 32 bits. */
export function rejectionLimit(limit: number): number {
  return Math.floor(0x1_0000_0000 / limit) * limit;
}

/** Fill one 32-bit word. Injectable so the bound can be tested at its edges. */
export type Uint32Source = (buf: Uint32Array<ArrayBuffer>) => void;

const cryptoSource: Uint32Source = (buf) => {
  crypto.getRandomValues(buf);
};

export function uniformBelow(limit: number, source: Uint32Source = cryptoSource): number {
  const bound = rejectionLimit(limit);
  const buf = new Uint32Array(1) as Uint32Array<ArrayBuffer>;
  for (;;) {
    source(buf);
    if (buf[0]! < bound) return buf[0]! % limit;
  }
}
