// CRC-32/ISO-HDLC (also called CRC-32, PKZIP, V-42 and XZ).
// [extension] point: a width/poly/init/refin/refout/xorout parameter object can
// add other CRCs without changing the receiver's byte-and-tag contract.
const POLY = 0xedb88320;
const TABLE = new Uint32Array(256);
const REVERSE_TOP = new Uint8Array(256);
for (let n = 0; n < 256; n += 1) {
  let value = n;
  for (let bit = 0; bit < 8; bit += 1) value = (value >>> 1) ^ ((value & 1) ? POLY : 0);
  TABLE[n] = value >>> 0;
  REVERSE_TOP[value >>> 24] = n;
}

export function crc32Step(register: number, byte: number): number {
  return (TABLE[(register ^ byte) & 0xff]! ^ (register >>> 8)) >>> 0;
}

/** Reverse one reflected register update when its input byte is known. */
export function crc32ReverseStep(next: number, byte: number): number {
  const index = REVERSE_TOP[next >>> 24]!;
  return (((next ^ TABLE[index]!) << 8) | (index ^ byte)) >>> 0;
}

export function crc32(bytes: Uint8Array): number {
  let register = 0xffffffff;
  for (const byte of bytes) register = crc32Step(register, byte);
  return (register ^ 0xffffffff) >>> 0;
}

export function crcHex(value: number): string {
  return (value >>> 0).toString(16).padStart(8, '0');
}
