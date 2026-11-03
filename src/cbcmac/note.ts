/**
 * "Agreed length: N bytes." for the fixed-length receiver's card.
 *
 * Separate from the panel so it can be asserted without a DOM: the panel's own
 * render path cannot be driven with a rogue <option>, because changing the
 * select retires the capture and tagging a non-numeric length fails before
 * anything reaches innerHTML.
 */
export function agreedLengthNote(variant: string, agreedValue: string): string {
  if (variant !== 'fixed') return '';
  return `Agreed length: ${Number(agreedValue)} bytes.`;
}
