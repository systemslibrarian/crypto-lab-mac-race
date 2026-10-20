# MAC Race — Raw CBC-MAC: fixed length only

Brief: `brief-extension.md`. Starting main: `bc4f683362e4a1e63b116e48e463c5a1d05ae880`.
Pages: https://systemslibrarian.github.io/crypto-lab-mac-race/

## Delivered

The eighth panel is Lesson 4, immediately before CMAC. Existing panel IDs,
primitive behavior, passphrase derivation, CRC lesson/runner, header, dark-theme
pin and footer are preserved. Later badges and tour steps are renumbered.
The opening statement scopes raw CBC-MAC to a shared, fixed message length.

The key stays in the oracle closure; pure one-/two-query splices see only
messages and tags. Actual zero-IV AES chaining produces every tag and verifier
result. The block display and aligned chain trace show the XOR cancellation.
Four receivers run against the same forged bytes and submitted raw tag, with
actual length/tag causes. Configuring the receiver for the forged length
correctly accepts and explains why the sender must share the restriction.
Length-prepending encodes the byte count as one 128-bit big-endian block.
Empty/non-block input refuses without padding. Fixed-work tag comparisons,
retirement, no-op handling, rotation and delayed AES completion are covered.

## Scoped correction and overlap

The pre-build available-clone grep found CBC-MAC inside AES Modes' CCM. The
remote Simon's Period target was also read: its fixed-length two-block toy
uses superposition queries. The new panel links it and explicitly distinguishes
the classical variable-length splice. Shared repositories were not edited.

The naive comparison of raw CBC-MAC and CMAC under one key hides a different
cross-protocol attack: knowing both raw AES(m) and CMAC(m) permits a splice
whose CMAC is CMAC(m). An independent unit regression pins that fact. Raw and
agreed-length controls share a key; length-prepended and CMAC controls use
independent keys. Each control additionally repeats the recipe with its OWN
authentic tags and verifies an honest message, so rejection cannot be explained
only by a different key. This qualification is visible on the page.

## Verification

- 85 unit tests passed (66 original, 19 new). Published pins traverse the
  original WebCrypto AES path: AES-128/256 ECB first blocks; all RFC 4493
  AES-128 CMAC cases (0/16/40/64 bytes) and K1/K2; all CSRC AES-256 cases
  (0/16/20/64 bytes). The 2016 SP 800-38B revision removed Appendix D examples;
  the existing comment now cites the actual CSRC examples file.
- The raw-CBC-MAC pin is explicitly DERIVED by folding SP 800-38A F.2.1's IV
  into its first block, not falsely credited as a published CBC-MAC vector.
  A test pins the attribution comment. Noble is test-only: 100 random raw
  chains, all CMAC lengths 0–100, 100 random one-/two-query forgeries, own-oracle
  controls, multi-block edge cases and the cross-protocol caveat are checked.
- §4.1a: eight panels and all eight tour steps, with the specified order.
- §4.1b: all 29 local Chromium browser checks passed. Five new claims derive
  forged bytes from public tags/messages, verify chain convergence, actual
  rejection causes, alarm/calm classes, general splices and stale-state guards.
- §4.1c: all six new concrete mutations killed. `cbcmac-mutation-evidence.json`
  records source patches, passing baselines, successful changed builds,
  zero-retry named assertion failures, exact restored hashes and green owning
  tests. Browser cases also hash served JavaScript. Original CRC cases and
  CI workflow remain unchanged. The new runner has its own npm command.
- §4.1d: after a real forgery, block alignment and tag equality pass together,
  the card says TAG VALID — AND FORGED, and the negative sentence is visible.
  Dropping the XOR or the sentence fails its owning assertion.
- Full desktop/380px accessibility walks and the 320px extension walk pass.
  Mobile, grayscale and deuteranopia views were inspected. A nested grid's
  min-width fix contains the trace table; its scroller is keyboard reachable.
  The longer page exposed a tour-start border contrast regression. Its border
  was strengthened and that fixed baseline entry removed; no exemption added.
- Local Chromium 153.0.8010.0 uses an ignored config because the pinned browser
  download was unavailable. CI still checks Chromium/Firefox/WebKit and the
  original CRC mutation gate before Pages deploy.

## Catalog handoff — no shared edits

Suggested sentence: “Forge a longer raw CBC-MAC message using only public tags,
then watch agreed length, length-prepending and CMAC enforce their boundaries.”
Suggested chip: `CBC-MAC Forgery`; retain all existing chips.
Concept deepened: **5. Message authentication**.
Implemented call sites: `src/cbcmac/cbcmac.ts`, `forge.ts`, `oracle.ts`, `panel.ts`;
`src/cmac.ts` adds only AES block export/validation and the byte-level CMAC API.
Prose only: random-IV, all-chaining-values, length-appended and ECBC extension
seams; no implementation claims for them.

Final main SHA and served-byte proof are recorded after publication. The fleet
sync check remains blocked by missing unrelated clones (14 of 236 available);
the catalog, counsel, census and checker are unchanged.
