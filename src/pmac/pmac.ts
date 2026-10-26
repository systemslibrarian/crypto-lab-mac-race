import { aesBlockEncrypt } from '../cbcmac/aesBlock';
import { equalTag, hex, xor } from '../cbcmac/cbcmac';

const BLOCK_BYTES = 16;

export type PmacLane = {
  index: number;
  blockHex: string;
  offsetHex: string;
  inputHex: string;
  outputHex: string;
};

export type PmacDetails = {
  version: 'Black–Rogaway 2002';
  blockCount: number;
  completeFinalBlock: boolean;
  lHex: string;
  lInverseHex: string;
  lanes: PmacLane[];
  finalBlockHex: string;
  paddedFinalBlockHex: string;
  checksumHex: string;
  finalInputHex: string;
  finalRule:
    | 'complete: XOR L·x^-1'
    | 'partial: 10* padding, no L·x^-1'
    | 'wrong control: complete block omitted L·x^-1'
    | 'wrong control: partial block incorrectly XORed L·x^-1';
  aesCallsPerMessage: number;
};

export type PmacResult = {
  tag: Uint8Array;
  tagHex: string;
  details: PmacDetails;
};

function copyBlock(block: Uint8Array): Uint8Array {
  if (block.length !== BLOCK_BYTES) throw new Error('PMAC field operations need one 16-byte block');
  return new Uint8Array(block);
}

/** Multiply by x in GF(2^128), using x^128 + x^7 + x^2 + x + 1. */
export function multiplyByX(block: Uint8Array): Uint8Array {
  block = copyBlock(block);
  const high = (block[0]! & 0x80) !== 0;
  const out = new Uint8Array(BLOCK_BYTES);
  let carry = 0;
  for (let i = BLOCK_BYTES - 1; i >= 0; i -= 1) {
    out[i] = ((block[i]! << 1) & 0xff) | carry;
    carry = block[i]! >>> 7;
  }
  if (high) out[BLOCK_BYTES - 1] ^= 0x87;
  return out;
}

/** Multiply by x^-1 in the same field (paper equation 2). */
export function divideByX(block: Uint8Array): Uint8Array {
  block = copyBlock(block);
  const low = (block[BLOCK_BYTES - 1]! & 1) !== 0;
  const out = new Uint8Array(BLOCK_BYTES);
  let carry = 0;
  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    out[i] = (block[i]! >>> 1) | carry;
    carry = (block[i]! & 1) << 7;
  }
  if (low) {
    out[0] ^= 0x80;
    out[BLOCK_BYTES - 1] ^= 0x43;
  }
  return out;
}

export function trailingZeroBits(index: number): number {
  if (!Number.isSafeInteger(index) || index <= 0) throw new Error('PMAC block indices must be positive safe integers');
  let value = index;
  let count = 0;
  while (value % 2 === 0) {
    value /= 2;
    count += 1;
  }
  return count;
}

function lPower(l: Uint8Array, exponent: number): Uint8Array {
  let value: Uint8Array = new Uint8Array(l);
  for (let i = 0; i < exponent; i += 1) value = multiplyByX(value);
  return value;
}

function splitMessage(message: Uint8Array): Uint8Array[] {
  const blockCount = Math.max(1, Math.ceil(message.length / BLOCK_BYTES));
  return Array.from({ length: blockCount }, (_, index) =>
    message.slice(index * BLOCK_BYTES, Math.min(message.length, (index + 1) * BLOCK_BYTES))
  );
}

function padFinal(block: Uint8Array): Uint8Array {
  if (block.length === BLOCK_BYTES) return new Uint8Array(block);
  const out = new Uint8Array(BLOCK_BYTES);
  out.set(block);
  out[block.length] = 0x80;
  return out;
}

function xorAll(blocks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(BLOCK_BYTES);
  for (const block of blocks) {
    if (block.length !== BLOCK_BYTES) throw new Error('PMAC checksum inputs must be complete blocks');
    for (let i = 0; i < BLOCK_BYTES; i += 1) out[i] ^= block[i]!;
  }
  return out;
}

async function computePmac(
  key: Uint8Array,
  message: Uint8Array,
  finalRule: 'correct' | 'inverted'
): Promise<PmacResult> {
  key = new Uint8Array(key);
  message = new Uint8Array(message);
  if (key.length !== 16 && key.length !== 32) throw new Error('PMAC-AES needs a 16- or 32-byte key');

  const l = await aesBlockEncrypt(key, new Uint8Array(BLOCK_BYTES));
  const lInverse = divideByX(l);
  const blocks = splitMessage(message);
  const finalBlock = blocks.at(-1)!;
  const complete = finalBlock.length === BLOCK_BYTES;

  let offset: Uint8Array = new Uint8Array(BLOCK_BYTES);
  const prepared = blocks.slice(0, -1).map((block, zeroIndex) => {
    const index = zeroIndex + 1;
    offset = xor(offset, lPower(l, trailingZeroBits(index)));
    const laneOffset = new Uint8Array(offset);
    const input = xor(block, laneOffset);
    return { index, block: new Uint8Array(block), offset: laneOffset, input };
  });

  // These calls have no data dependency on one another. Promise.all expresses
  // that property without claiming the browser or host schedules them in parallel.
  const outputs = await Promise.all(prepared.map(({ input }) => aesBlockEncrypt(key, input)));
  const paddedFinal = padFinal(finalBlock);
  const checksum = xorAll([...outputs, paddedFinal]);
  const applyInverse = finalRule === 'correct' ? complete : !complete;
  const finalInput = applyInverse ? xor(checksum, lInverse) : new Uint8Array(checksum);
  const tag = await aesBlockEncrypt(key, finalInput);

  return {
    tag: new Uint8Array(tag),
    tagHex: hex(tag),
    details: {
      version: 'Black–Rogaway 2002',
      blockCount: blocks.length,
      completeFinalBlock: complete,
      lHex: hex(l),
      lInverseHex: hex(lInverse),
      lanes: prepared.map((lane, index) => ({
        index: lane.index,
        blockHex: hex(lane.block),
        offsetHex: hex(lane.offset),
        inputHex: hex(lane.input),
        outputHex: hex(outputs[index]!)
      })),
      finalBlockHex: hex(finalBlock),
      paddedFinalBlockHex: hex(paddedFinal),
      checksumHex: hex(checksum),
      finalInputHex: hex(finalInput),
      finalRule: finalRule === 'correct'
        ? (complete ? 'complete: XOR L·x^-1' : 'partial: 10* padding, no L·x^-1')
        : (complete ? 'wrong control: complete block omitted L·x^-1' : 'wrong control: partial block incorrectly XORed L·x^-1'),
      aesCallsPerMessage: blocks.length
    }
  };
}

/** Exact byte-aligned PMAC from Black–Rogaway 2002, with a full 128-bit tag. */
export async function pmac2002(key: Uint8Array, message: Uint8Array): Promise<PmacResult> {
  return computePmac(key, message, 'correct');
}

/** Deliberately nonconforming final-block rule for the learner-facing negative control. */
export async function pmacWrongFinalRuleForLesson(key: Uint8Array, message: Uint8Array): Promise<PmacResult> {
  return computePmac(key, message, 'inverted');
}

export async function verifyPmac2002(
  key: Uint8Array,
  message: Uint8Array,
  candidateTag: Uint8Array
): Promise<boolean> {
  try {
    return equalTag((await pmac2002(key, message)).tag, new Uint8Array(candidateTag));
  } catch {
    return false;
  }
}
