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

export function runTimingSelfTest(): boolean {
  const a = toBytes('abcdef');
  const b = toBytes('abcdef');
  const c = toBytes('abcdeg');
  return naiveEqual(a, b) && !naiveEqual(a, c) && constantTimeEqual(a, b) && !constantTimeEqual(a, c);
}
