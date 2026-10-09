import { crc32, crc32ReverseStep, crc32Step } from './crc32';

/** Public arithmetic only. The affine offset is the CRC of the all-zero message. */
export function repairCrc(original: Uint8Array, altered: Uint8Array, originalCrc: number): number {
  if (original.length !== altered.length) throw new Error('The affine shortcut needs equal byte lengths; 3b handles length changes.');
  const delta = original.map((byte, i) => byte ^ altered[i]!);
  return (originalCrc ^ crc32(delta) ^ crc32(new Uint8Array(original.length))) >>> 0;
}

/**
 * Run the target register backwards through four zero bytes via an inverse
 * lookup on the table's high byte. Then choose each appended byte to cancel
 * the low byte of the difference between the real and target registers.
 * Each update shifts the remaining difference by eight bits; four updates
 * clear all 32 bits. This is the reverse-table method of Stigge et al. §4.
 * [extension] point: forcing bytes at an arbitrary position needs prefix and
 * suffix register transforms (Stigge et al., section 5).
 */
export function forceCrc(message: Uint8Array, target: number): Uint8Array {
  const withPatch = new Uint8Array(message.length + 4);
  withPatch.set(message);
  const desired = (target ^ 0xffffffff) >>> 0;
  let reference = desired;
  for (let i = 0; i < 4; i += 1) reference = crc32ReverseStep(reference, 0);
  let state = (crc32(message) ^ 0xffffffff) >>> 0;
  for (let i = 0; i < 4; i += 1) {
    const byte = (state ^ reference) & 0xff;
    withPatch[message.length + i] = byte;
    state = crc32Step(state, byte);
    reference = crc32Step(reference, 0);
  }
  if (state !== desired) throw new Error('CRC register reversal failed');
  return withPatch;
}
