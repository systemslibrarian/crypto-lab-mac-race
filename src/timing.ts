export type TimingRow = {
  label: string;
  naiveMs: number;
  constantMs: number;
};

export type TimingDemo = {
  rows: TimingRow[];
  summary: string;
};

function toBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function naiveEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function measure(compare: (a: Uint8Array, b: Uint8Array) => boolean, a: Uint8Array, b: Uint8Array, rounds: number): number {
  const start = performance.now();
  for (let i = 0; i < rounds; i += 1) {
    compare(a, b);
  }
  const end = performance.now();
  return end - start;
}

export function runTimingDemo(rounds = 50000): TimingDemo {
  const real = toBytes('mac=5f93b8f7ccf93f2af1b047b4f4e8a2d3');
  const cases = [
    { label: 'Mismatch at byte 1', value: toBytes('Xac=5f93b8f7ccf93f2af1b047b4f4e8a2d3') },
    { label: 'Mismatch at middle', value: toBytes('mac=5f93b8f7ccf93f2af1b04700f4e8a2d3') },
    { label: 'Mismatch at final byte', value: toBytes('mac=5f93b8f7ccf93f2af1b047b4f4e8a2d4') }
  ];

  const rows = cases.map((entry) => ({
    label: entry.label,
    naiveMs: measure(naiveEqual, real, entry.value, rounds),
    constantMs: measure(constantTimeEqual, real, entry.value, rounds)
  }));

  return {
    rows,
    summary: 'Naive comparison exits early and leaks prefix-match timing. Constant-time comparison keeps timing flatter.'
  };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export type RecoveryProgress = {
  byteIndex: number;
  byteValue: number;
  recoveredHex: string;
  totalBytes: number;
  oracleQueries: number;
};

export type RecoveryResult = {
  trueTagHex: string;
  recoveredTagHex: string;
  bytesRecovered: number;
  totalBytes: number;
  oracleQueries: number;
  success: boolean;
};

// The attacker's only tool is a simulated server endpoint that uses
// `naiveEqual` for tag comparison. Real `performance.now()` in a browser
// is too noisy to recover bytes, so the oracle below reports its
// prefix-match length directly — the statistical equivalent of a real
// attacker who averages enough samples to extract that signal. The
// attack methodology (recover one byte at a time, keep whichever
// candidate produced the longest "time") is identical to a real-world
// remote-timing attack against a non-constant-time tag comparator.
function makeNaiveCompareOracle(tagLength: number) {
  const trueTag = crypto.getRandomValues(new Uint8Array(tagLength));
  let queries = 0;
  return {
    trueTag,
    queries: () => queries,
    measure(candidate: Uint8Array): number {
      queries += 1;
      let units = 0;
      for (let i = 0; i < trueTag.length; i += 1) {
        units += 1;
        if (trueTag[i] !== candidate[i]) break;
      }
      return units;
    }
  };
}

export async function recoverTagByTimingAttack(
  tagLength = 16,
  onProgress?: (p: RecoveryProgress) => void,
  bytesToRecover?: number
): Promise<RecoveryResult> {
  const target = Math.min(bytesToRecover ?? tagLength, tagLength);
  const oracle = makeNaiveCompareOracle(tagLength);
  const recovered = new Uint8Array(tagLength);

  for (let i = 0; i < target; i += 1) {
    let bestByte = 0;
    let bestUnits = -1;
    for (let candidate = 0; candidate < 256; candidate += 1) {
      recovered[i] = candidate;
      const units = oracle.measure(recovered);
      if (units > bestUnits) {
        bestUnits = units;
        bestByte = candidate;
      }
    }
    recovered[i] = bestByte;
    if (onProgress) {
      onProgress({
        byteIndex: i,
        byteValue: bestByte,
        recoveredHex: toHex(recovered.slice(0, i + 1)),
        totalBytes: tagLength,
        oracleQueries: oracle.queries()
      });
    }
    await new Promise((resolve) => setTimeout(resolve, 35));
  }

  const recoveredHex = toHex(recovered.slice(0, target));
  const trueHex = toHex(oracle.trueTag.slice(0, target));
  return {
    trueTagHex: toHex(oracle.trueTag),
    recoveredTagHex: recoveredHex,
    bytesRecovered: target,
    totalBytes: tagLength,
    oracleQueries: oracle.queries(),
    success: recoveredHex === trueHex
  };
}

export function runTimingSelfTest(): boolean {
  const a = toBytes('abcdef');
  const b = toBytes('abcdef');
  const c = toBytes('abcdeg');
  return naiveEqual(a, b) && !naiveEqual(a, c) && constantTimeEqual(a, b) && !constantTimeEqual(a, c);
}
