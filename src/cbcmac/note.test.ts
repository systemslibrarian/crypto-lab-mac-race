import { describe, expect, it } from 'vitest';
import { agreedLengthNote } from './note';

/**
 * The guard for CodeQL js/xss-through-dom (sink src/cbcmac/panel.ts). The
 * receiver's agreed length is a <select> value -- DOM text however it is typed
 * -- and it is shown back inside the panel's innerHTML.
 *
 * The render path cannot be driven with a rogue <option>: changing the select
 * retires the capture, and tagging a non-numeric length fails before anything
 * is rendered. So the sentence is asserted directly.
 */
describe('agreedLengthNote', () => {
  it('reports every real option unchanged', () => {
    for (let blocks = 1; blocks <= 16; blocks += 1) {
      const bytes = 16 * blocks;
      expect(agreedLengthNote('fixed', String(bytes))).toBe(`Agreed length: ${bytes} bytes.`);
    }
  });

  it('cannot emit markup from a value that is not a number', () => {
    for (const payload of [
      '<img src=x data-injected=yes>',
      '16"><svg onload=1>',
      "16' onmouseover='x",
      '<script>alert(1)</script>',
    ]) {
      const out = agreedLengthNote('fixed', payload);
      expect(out).not.toContain('<');
      expect(out).not.toContain('>');
      expect(out).not.toContain('"');
      expect(out).toBe('Agreed length: NaN bytes.');
    }
  });

  it('says nothing for the other three receivers', () => {
    for (const v of ['raw', 'prepended', 'cmac']) {
      expect(agreedLengthNote(v, '16')).toBe('');
    }
  });
});
