const BLOCK_BYTES = 16;

export type AesTask = { label: string; block?: number; dependsOn: string[] };
export type AesWave = { round: number; tasks: AesTask[] };

export type MacSchedule = {
  messageBytes: number;
  blockCount: number;
  lanes: number;
  keySetupAesCallsEach: 1;
  pmac: { aesWork: number; aesSpan: number; waves: AesWave[] };
  cmac: { aesWork: number; aesSpan: number; waves: AesWave[] };
};

function chunks<T>(items: T[], width: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += width) out.push(items.slice(i, i + width));
  return out;
}

/**
 * Deterministic AES-call dependency model. It excludes XOR/offset work and
 * assumes E_K(0^128)-derived subkeys/offsets were prepared once per key.
 */
export function modelPmacVsCmac(messageBytes: number, lanes: number): MacSchedule {
  if (!Number.isSafeInteger(messageBytes) || messageBytes < 0) throw new Error('Message length must be a nonnegative safe integer');
  if (!Number.isSafeInteger(lanes) || lanes < 1 || lanes > 64) throw new Error('AES lanes must be an integer from 1 to 64');
  const blockCount = Math.max(1, Math.ceil(messageBytes / BLOCK_BYTES));

  const independent = Array.from({ length: Math.max(0, blockCount - 1) }, (_, index) => ({
    label: `PMAC block ${index + 1}`,
    block: index + 1,
    dependsOn: [] as string[]
  }));
  const pmacWaves: AesWave[] = chunks(independent, lanes).map((tasks, index) => ({ round: index + 1, tasks }));
  pmacWaves.push({
    round: pmacWaves.length + 1,
    tasks: [{
      label: 'PMAC final AES',
      block: blockCount,
      dependsOn: independent.map((task) => task.label)
    }]
  });

  const cmacWaves: AesWave[] = Array.from({ length: blockCount }, (_, index) => ({
    round: index + 1,
    tasks: [{
      label: `CMAC block ${index + 1}`,
      block: index + 1,
      dependsOn: index === 0 ? [] : [`CMAC block ${index}`]
    }]
  }));

  return {
    messageBytes,
    blockCount,
    lanes,
    keySetupAesCallsEach: 1,
    pmac: { aesWork: blockCount, aesSpan: pmacWaves.length, waves: pmacWaves },
    cmac: { aesWork: blockCount, aesSpan: cmacWaves.length, waves: cmacWaves }
  };
}
