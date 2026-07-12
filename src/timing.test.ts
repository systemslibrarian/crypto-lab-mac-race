import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  naiveEqual,
  recoverTagByTimingAttack,
  runTimingSelfTest,
} from './timing';

const enc = new TextEncoder();

describe('comparison primitives', () => {
  it('self-test passes', () => {
    expect(runTimingSelfTest()).toBe(true);
  });

  it('naiveEqual and constantTimeEqual agree on equality (any input)', () => {
    const cases: [string, string][] = [
      ['', ''],
      ['a', 'a'],
      ['abc', 'abc'],
      ['abc', 'abd'],
      ['abc', 'abcd'],
      ['xyz', 'xy'],
    ];
    for (const [a, b] of cases) {
      const x = enc.encode(a);
      const y = enc.encode(b);
      expect(constantTimeEqual(x, y)).toBe(naiveEqual(x, y));
    }
  });

  it('constantTimeEqual returns false on length mismatch without indexing OOB', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1]))).toBe(false);
  });
});

describe('timing-attack oracle byte recovery', () => {
  it('recovers the full tag one byte at a time via the prefix-match oracle', async () => {
    const result = await recoverTagByTimingAttack(8);
    expect(result.success).toBe(true);
    expect(result.recoveredTagHex).toBe(result.trueTagHex.slice(0, 16));
    // 256 candidates per byte position → 8 * 256 oracle queries.
    expect(result.oracleQueries).toBe(8 * 256);
  });

  it('recovering a partial prefix still matches the true prefix', async () => {
    const result = await recoverTagByTimingAttack(16, undefined, 4);
    expect(result.bytesRecovered).toBe(4);
    expect(result.recoveredTagHex).toBe(result.trueTagHex.slice(0, 8));
  });
});
