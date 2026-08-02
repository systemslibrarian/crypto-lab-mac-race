export type TimingRow = {
  label: string;
  naiveMs: number;
  constantMs: number;
};

export type TimingDemo = {
  rows: TimingRow[];
  summary: string;
};

export function summarizeTimingRows(rows: TimingRow[]): string {
  const spread = (values: number[]) => Math.max(...values) - Math.min(...values);
  const naiveSpread = spread(rows.map((row) => row.naiveMs));
  const constantSpread = spread(rows.map((row) => row.constantMs));
  const comparison = constantSpread <= naiveSpread
    ? 'The full-scan comparison was flatter in this run.'
    : 'Measurement noise outweighed the expected shape in this run; repeat the measurement.';
  return `Measured spread across mismatch positions: naive ${naiveSpread.toFixed(3)} ms; full-scan ${constantSpread.toFixed(3)} ms. ${comparison} JavaScript timing is not a constant-time guarantee.`;
}

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
    summary: summarizeTimingRows(rows)
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
    // Models a non-constant-time `memcmp(candidate, trueTag)` against the
    // stored tag: the loop exits at the first differing byte, so the number
    // of iterations (the timing signal) equals the prefix-match length + 1
    // for a mismatch, and the full candidate length for a total prefix match.
    // The attacker submits a candidate of exactly the length decided so far.
    measure(candidate: Uint8Array): number {
      queries += 1;
      const n = Math.min(candidate.length, trueTag.length);
      let units = 0;
      for (let i = 0; i < n; i += 1) {
        units += 1;
        if (candidate[i] !== trueTag[i]) return units;
      }
      // Every submitted byte matched: the comparator ran the full length,
      // which is the maximal timing signal for this prefix.
      return units + 1;
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
      // Probe only the recovered prefix plus this guessed byte. Trailing
      // (not-yet-recovered) bytes are omitted so they cannot coincidentally
      // extend the match and mask which guess actually matched at position i.
      // This mirrors a real remote-timing attack, where the attacker submits
      // exactly the bytes decided so far and reads the prefix-match signal.
      const units = oracle.measure(recovered.subarray(0, i + 1));
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
