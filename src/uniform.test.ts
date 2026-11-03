import { describe, expect, it } from 'vitest';
import { rejectionLimit, uniformBelow, type Uint32Source } from './uniform';

/**
 * The rejection bound, at its edges.
 *
 * A statistical test cannot find an off-by-one here: moving the bound by one
 * changes the distribution by about 2**-32. It is a boundary condition, so it
 * is tested as one, with the 32-bit source injected rather than sampled.
 */
describe('rejection bound', () => {
  /** Yields the given raw words in order, counting how many draws were taken. */
  function feed(words: number[], calls: number[] = []): Uint32Source {
    let i = 0;
    return (buf) => {
      calls.push(i);
      buf[0] = words[Math.min(i, words.length - 1)]!;
      i += 1;
    };
  }

  // limit = 10 on purpose: 2**32 % 10 is 6, so the discarded tail is six wide
  // and a multi-redraw can be exercised. At limit = 3 the tail is one value and
  // bound + 1 wraps to 0, which is accepted.
  const limit = 10;
  // Derived WITHOUT calling the code under test: taking the bound from
  // rejectionLimit would move this expectation along with any mutation of it.
  const bound = 0x1_0000_0000 - (0x1_0000_0000 % limit);

  it('is the largest multiple of the limit inside 32 bits', () => {
    expect(rejectionLimit(limit)).toBe(bound);
    expect(bound % limit).toBe(0);
    expect(0x1_0000_0000 - bound).toBe(0x1_0000_0000 % limit);
  });

  it('uses the largest accepted raw value, in one draw', () => {
    const calls: number[] = [];
    expect(uniformBelow(limit, feed([bound - 1], calls))).toBe((bound - 1) % limit);
    expect(calls).toHaveLength(1);
  });

  it('redraws on the smallest rejected raw value, taking two draws', () => {
    const calls: number[] = [];
    expect(uniformBelow(limit, feed([bound, 7], calls))).toBe(7 % limit);
    expect(calls).toHaveLength(2);
  });

  it('keeps redrawing while the source stays in the tail', () => {
    const calls: number[] = [];
    expect(uniformBelow(limit, feed([bound, bound + 3, bound + 5, 5], calls))).toBe(5 % limit);
    expect(calls).toHaveLength(4);
  });

  it('covers every value in range and nothing outside it', () => {
    const seen = new Set<number>();
    for (let v = 0; v < 64; v += 1) seen.add(uniformBelow(limit, feed([v])));
    expect([...seen].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });
});
