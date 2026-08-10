/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 1.51, required: 3.0, unverified: false },
  "control-boundary|button#cl-theme-toggle.cl-btn.cl-icon": { ratio: 1.51, required: 3.0, unverified: false },
  "control-boundary|button#cmac-verify": { ratio: 2.76, required: 3.0, unverified: false },
  "control-boundary|button#ghash-attack": { ratio: 2.88, required: 3.0, unverified: false },
  "control-boundary|button#ghash-verify": { ratio: 2.76, required: 3.0, unverified: false },
  "control-boundary|button#hmac-verify": { ratio: 2.76, required: 3.0, unverified: false },
  "control-boundary|button#le-forge": { ratio: 2.88, required: 3.0, unverified: false },
  "control-boundary|button#le-verify-hmac": { ratio: 2.66, required: 3.0, unverified: false },
  "control-boundary|button#le-verify-raw": { ratio: 2.81, required: 3.0, unverified: false },
  "control-boundary|button#poly-attack": { ratio: 2.88, required: 3.0, unverified: false },
  "control-boundary|button#poly-verify": { ratio: 2.76, required: 3.0, unverified: false },
  "control-boundary|button#recovery-run": { ratio: 2.88, required: 3.0, unverified: false },
  "control-boundary|button#tour-end": { ratio: 2.64, required: 3.0, unverified: false },
  "control-boundary|button#tour-next": { ratio: 2.59, required: 3.0, unverified: false },
  "control-boundary|button#tour-prev": { ratio: 2.55, required: 3.0, unverified: false },
  "control-boundary|button#tour-start": { ratio: 2.7, required: 3.0, unverified: false },
  "control-boundary|input#cmac-verify-tag": { ratio: 2.76, required: 3.0, unverified: false },
  "control-boundary|input#hmac-verify-tag": { ratio: 2.76, required: 3.0, unverified: false },
  "control-boundary|input#le-append": { ratio: 2.88, required: 3.0, unverified: false },
  "control-boundary|input#recovery-bytes": { ratio: 2.88, required: 3.0, unverified: false }
};
