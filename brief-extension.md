# Extension brief — `crypto-lab-mac-race`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-mac-race` at `bc4f683362e4` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap: Katz–Lindell,
*Introduction to Modern Cryptography*, 3rd ed. (CRC Press, 2021), §4.4.1 — Construction 4.9
(basic CBC-MAC), Theorem 4.10 (secure **for fixed-length messages only**), Figure 4.2 (length
prepending), Exercises 4.13–4.15. The book's references point to CMAC as RFC 4493.

**Verdict: extension.** Add one new lesson panel, "Raw CBC-MAC", placed just before the
existing CMAC lesson. Also close a known-answer gap in the existing CMAC tests (see Tests).

## What the lab has now

Read at `bc4f683362e4`:

- **CMAC**, hand-rolled in `src/cmac.ts`:
  - `aesBlockEncrypt` (`cmac.ts:70`, module-private) — one AES block via single-block AES-CBC
    with a zero IV, keeping the first 16 bytes.
  - `deriveSubkeys` (`:77`) for K1/K2, and `computeCmacBytes` (`:117`, module-private), which
    chains blocks and applies K1/K2.
  - `computeCmac(message: string, keyInput: string)` (`:113`) and `verifyCmac` (`:151`).
  - `deriveAes256Key` (`:39`) accepts exactly 64 hex characters as a raw key and otherwise
    hashes a passphrase with SHA-256. The CMAC panel is therefore AES-256 only.
- **CMAC known answers:** `src/cmac.test.ts` pins **one** published vector, the single-block
  (16-byte) AES-256 tag `28a7023f…c35c`, through `runCmacSelfTest` (`cmac.ts:165`). Its
  comment (`cmac.test.ts:6`) cites "SP 800-38B Appendix D.3, Example 10". The other CMAC tests
  are properties (K1 ≠ K2, padding byte present, determinism). **No published multi-block
  vector reaches the chaining loop**, which is the defect class Paul's KAT rule names: a wrong
  chaining step would pass a one-block vector.
- **The panel grid:** a guided tour over seven panels (`LESSON_STEPS`, `src/ui.ts:290`).
  - p0 Checksum vs MAC comes from `src/crc/panel.ts`.
  - p1 HMAC, p5 length extension, p2 CMAC (`ui.ts:417`), p3 Poly1305, p4 GHASH, p6 timing.
  - Lesson badges are hard-coded in each panel's HTML.
  - `e2e/gate.ts:99` asserts `.page section.panel` count **7**, and `e2e/claims.spec.ts:646`
    asserts "the guided tour highlights the seven panels in pedagogical order".
- **The precedent for exactly this kind of extension:** the CRC-vs-MAC lesson lives in its own
  directory (`src/crc/`), exports `checksumPanelHtml` and `wireChecksumPanel`, and carries its
  own scripted mutation runner, `scripts/check-crc-mutations.mjs` (`npm run test:mutations`).
  That runner records concrete patches, refuses an anchor that occurs more than once, checks
  the build and that the bundle hash moved, and requires a named test to fail.
- **Dependencies:** `@noble/ciphers` ^2.4.0. In the published 2.4.0 package `aes.js` exports
  `ecb` and `cmac` (checked in the npm tarball while writing this brief). Use them only as
  independent test references, never in the shipping path.

Nothing in this lab shows why CMAC exists. The CMAC panel presents the K1/K2 tweak as a
recipe. The reason for it — raw CBC-MAC is forgeable as soon as messages may differ in length —
is the lesson K-L teaches in §4.4.1.

**Overlap check.** Before building, grep the sibling clones for `cbc.?mac` and report what you
find. When this brief was written, CBC-MAC appeared:

- inside CCM in `crypto-lab-aes-modes`;
- as FF1's internal PRF in `crypto-lab-format-ward` and `crypto-lab-fte`;
- in prose in `crypto-lab-glass-box` and `crypto-lab-padding-oracle`;
- as the target of a **quantum** forgery in `crypto-lab-simon-period` (`94d86ffa67fa`,
  `src/crypto/targets.ts:251`, raw two-block CBC-MAC over a toy n-bit permutation, with
  Simon's algorithm under superposition queries).

None of these runs the classical length-extension splice.

## What to add — lesson "Raw CBC-MAC: fixed length only"

**Plain-language intro:** CBC-MAC chains AES across a message and keeps the last block as
the tag. If everyone agrees in advance how long messages are, that is a sound MAC. If the
receiver accepts messages of any length, a tag you have seen lets you build a longer message
with the same tag, without the key.

**The headline mechanism, shown:** the chaining values, drawn block by block (reuse the
existing `.hex.stepper` styling). After the attacker's first block the chain value **is** the
tag `t`. XORing `t` into the next block cancels it and restarts the chain exactly where a fresh
message would start. The learner watches the two chains converge onto the same final value.

**Three acts, each against a real AES verifier:**

1. **Fixed length.** Raw CBC-MAC (Construction 4.9): AES, zero IV, no padding, messages a
   multiple of 16 bytes. Show Theorem 4.10's statement next to it, scoped as the book scopes
   it: secure when every message has the same, agreed length.
2. **The splice (break it yourself).** One MAC query on a one-block `m` returns `t`. The
   learner presses "Forge" and the page builds `m ‖ (m ⊕ t)`, submits it with tag `t`, and a
   **variable-length verifier** that recomputes raw CBC-MAC with the secret key accepts it →
   `ACCEPTED — FORGED`. Then the general form, which needs two MAC queries: given `(m, t)` and
   `(m′, t′)` with `m′ = m′₁ ‖ … ‖ m′_ℓ`, the message `m ‖ (m′₁ ⊕ t) ‖ m′₂ ‖ … ‖ m′_ℓ` carries tag `t′`.
   This brief's author checked both identities with an independent AES implementation; the
   unit tests must re-check them (see Tests). K-L Exercise 4.13(a) asks for a forgery of this
   kind.
3. **The fixes, each run against the same forged bytes:**
   - **Agreed length** — a verifier that rejects any length but the agreed one. Rejected, and
     the reason named is "length", not "tag".
   - **Length prepended** (K-L Figure 4.2) — MAC over `⟨|m|⟩ ‖ m`, with the length encoded as
     one 16-byte block. The spliced message's tag no longer matches. Rejected; reason "tag".
   - **CMAC** — the lab's existing CMAC, reached through a new bytes-level entry point.
     Rejected; reason "tag". Point the learner at the existing CMAC lesson for *how*.

**Classical vs quantum, stated precisely on the page:** the splice needs **variable-length**
messages and one or two **classical** tags. Simon's Period forges **fixed-length** two-block
CBC-MAC — the setting Theorem 4.10 proves secure classically — but only with **superposition**
queries to the MAC. The two attacks don't overlap, and the page should say so in one sentence
with a link.

## Placement and numbering

Insert the panel (`id="p7"` — ids are not order) into the grid and into `LESSON_STEPS`
immediately **before** CMAC. CMAC's motivation then precedes it. Renumber the lesson badges and
tour titles that follow (CMAC becomes Lesson 5, through Timing as Lesson 8). Renumbering labels
is not restructuring content. Update `gate.ts:99` (7 → 8 panels) and the tour test at
`claims.spec.ts:646` ("seven" → "eight", plus the order list).

## SECURITY / CORRECTNESS INVARIANTS

1. Every forgery is checked by a verifier that **recomputes** the MAC with the secret key. The
   page never decides "accepted" by comparing with something the attacker computed.
2. The attacker's code path never holds the key. It sees only the tags the MAC oracle returns.
   Keep the key in a closure in the oracle module and test that the forge function's inputs
   are `(m, t)` only.
3. The vulnerable variable-length verifier is never the default framing. It is labelled
   "deliberately vulnerable: accepts any length" on screen, and the fixed-length verifier sits
   beside it.
4. Raw CBC-MAC refuses inputs that aren't a whole number of blocks, with a named code
   (`NOT_BLOCK_ALIGNED`). It never pads silently, because padding is a different construction.
5. The length-prepended variant encodes the length in exactly one block, big-endian. That
   encoding is stated on screen.
6. Constant-time comparison for every verifier: reuse the pattern in `verifyCmac`
   (`cmac.ts:151`).
7. Existing CMAC behaviour (string API, passphrase-to-AES-256 derivation) is unchanged. The new
   bytes API is additive.

## ARCHITECTURE

New directory, mirroring `src/crc/`:

- `src/cbcmac/aesBlock.ts` — export the single-block AES the lab already trusts. Either export
  `aesBlockEncrypt` from `cmac.ts` and re-export it here, or move it here and import it into
  `cmac.ts`. Pick whichever leaves `cmac.ts`'s diff smallest. Accept 16- or 32-byte keys only:
  Chromium's WebCrypto has no 192-bit AES, so don't offer it.
- `src/cbcmac/cbcmac.ts` — `rawCbcMac(key, msg)`, `prependLengthCbcMac(key, msg)`,
  `verifyFixedLength`, `verifyAnyLength`, `verifyPrepended`. Failure codes are exported
  constants: `NOT_BLOCK_ALIGNED`, `LENGTH_MISMATCH`, `TAG_MISMATCH`.
- `src/cbcmac/oracle.ts` — `makeMacOracle(variant)`. It holds a fresh random key and exposes
  `mac(m)` and `verify(m, t)` only.
- `src/cbcmac/forge.ts` — `spliceOne(m, t)` and `spliceTwo(m, t, mPrime)`. Pure byte
  functions with no key.
- `src/cbcmac/panel.ts` — `cbcMacPanelHtml` plus `wireCbcMacPanel`, in the same shape as
  `src/crc/panel.ts`.
- `src/cmac.ts` — add an exported `cmacBytes(keyBytes: Uint8Array, msg: Uint8Array)` that
  `computeCmacBytes` delegates to. That is the only change to this file besides the
  `aesBlockEncrypt` export.
- `scripts/check-cbcmac-mutations.mjs` plus an npm script `test:mutations:cbcmac`, copied from
  `check-crc-mutations.mjs`.

## UI

- The message is shown as 16-byte block cells (hex over text, matching the lab's style). A
  "Get tag" button calls the oracle. "Forge" builds and shows the spliced message, with the
  inserted block labelled `m ⊕ t`.
- Three verifier cards side by side: "Accepts any length (vulnerable)", "Agreed length",
  "Length prepended", plus a CMAC card. Each has its own verdict chip.
- A chaining-value stepper for the honest message and the forged one, aligned so the converging
  chain values sit in the same column.
- Below the cards, the "classical vs quantum" sentence with the Simon's Period link.
- Retirement: editing `m` or rotating the key clears every verdict and says why. Repeating the
  same input does not. The CRC lesson already handles an in-flight result after an edit
  (`claims.spec.ts:585`); copy that guard.

## VISUAL SEMANTICS

- **The vulnerable verifier accepting the forgery** → ALARM: "✕ ACCEPTED — FORGED". Never green.
  The CRC mutation list already contains "accepted forgery painted green"; add the same case here.
- **A fixed verifier rejecting the forgery** → the system working: "✓ rejected — tag mismatch" or
  "✓ rejected — wrong length", in calm styling.
- **Honest tags verifying** → calm.
- Icon plus text plus colour every time. Check the page in grayscale.

## EDGE CASES

- Message not a multiple of 16 bytes → `NOT_BLOCK_ALIGNED`, naming the length and the next
  valid one.
- Empty message → refuse for raw CBC-MAC; with zero blocks the "tag" would be the IV.
  Explain in a tooltip.
- `spliceTwo` when `m′` is a single block → that is the one-block case. Show it, don't refuse.
- The agreed-length verifier configured for the forged length (e.g. "2 blocks" with a
  one-block oracle message) → it accepts the forgery. Teach this: agreeing on a length helps
  only if the sender also only ever MACs that length (K-L Exercise 4.13(b) is the related
  case).
- Key rotation mid-lesson → retire every tag and verdict.

## EXTENSION SEAMS

1. **Random-IV CBC-MAC** and **output-all-chaining-values CBC-MAC** (K-L Exercise 4.14(a)/(b)):
   both are forgeable even at fixed length. If you add them, cite the book. No primary
   publication for these folklore forgeries was located while writing this brief, so don't
   invent one.
2. **Length appended instead of prepended** — insecure (K-L Exercise 4.15). Needs a multi-query
   forgery; not built.
3. **ECBC / encrypt-last-block with a second key** (K-L's second fix), as a fourth card.

## Tests

**Known answers (unit).** Every vector must be checked through the lab's own WebCrypto path,
not through noble:

- **AES block function:** NIST SP 800-38A F.1.1 (AES-128) and F.1.5 (AES-256) ECB block #1, via
  `aesBlock.ts`: `3ad77bb4…ef97` and `f3eed1bd…81f8`.
- **CMAC, AES-128 — RFC 4493 §4, Examples 1–4** (0, 16, 40, 64 bytes) via `cmacBytes`. Example 3
  (40 bytes, partial final block) and Example 4 (64 bytes) exercise the chaining loop and both
  subkeys. Also pin the RFC's K1 `fbeed618…a8de` and K2 `f7ddac30…513b`.
- **CMAC, AES-256 — NIST CSRC "Examples with Intermediate Values", `AES_CMAC.pdf`:** 0, 16, 20 and
  64-byte messages under key `603deb10…dff4`, with tags `028962f6…d983`, `28a7023f…c35c`,
  `156727dc…6d93` and `e1992190…5410`. These close the multi-block gap in the existing tests.
  The comment at `cmac.test.ts:6` cites "SP 800-38B Appendix D.3, Example 10". Verify whether
  the revision it names still carries that appendix (SP 800-38B is "May 2005, updated
  10/6/2016"). If it doesn't, re-anchor the comment to the CSRC examples page rather than
  carrying the old numbering forward.
- **Raw CBC-MAC, a derived known answer.** SP 800-38A publishes **no** CBC-MAC vector, so don't
  credit it with one. It does publish CBC encryption, F.2.1 CBC-AES128.Encrypt, with key
  `2b7e1516…4f3c` and IV `00010203…0e0f`. CBC encryption's last ciphertext block is the CBC-MAC
  of the message with the IV folded into its first block. So:
  `rawCbcMac(key, 6bc0bce12a459991e134741a7f9e1925 ‖ ae2d8a57…8e51 ‖ 30c81c46…52ef ‖ f69f2445…3710)`
  must equal F.2.1's Block #4 ciphertext, `3ff1caa1681fac09120eca307586e1a7`. The first block is
  F.2.1's published Block #1 "Input Block". Write that derivation in the test's comment, and add
  a test asserting the comment's attribution sentence, so it can't drift into "SP 800-38A
  CBC-MAC vector". (This brief's author confirmed the equality with an independent AES.)
- **Independent cross-checks:** `rawCbcMac` against a CBC-MAC built in the test from
  `@noble/ciphers` `ecb` with `disablePadding`, for random 1–8-block messages. `cmacBytes`
  against noble's `cmac` for random lengths 0–100 bytes.
- **Forgery algebra:**
  - `verifyAnyLength(spliceOne(m, t), t)` is true for 100 random keys and messages.
  - `verifyAnyLength(spliceTwo(m, t, m′), t′)` is true likewise.
  - `verifyPrepended` and `cmacBytes` reject both forgeries.
  - `verifyFixedLength` rejects with `LENGTH_MISMATCH`.

**Claims (`e2e/claims.spec.ts`, §4.1b):**

- **Re-derivation.** The page prints the oracle's tag `t`, the forged message and the
  vulnerable verifier's verdict. In the test, check that the forged message's second block
  equals `m ⊕ t` byte for byte from the printed values. Assert the verdict is the ALARM
  acceptance.
- **Each failure path names its cause.** Unaligned input names its length. The fixed-length
  verifier names "length". The prepended and CMAC verifiers name "tag".
- **Retirement and no-op guard**, as in the CRC tests.
- **Update the existing tour test (`claims.spec.ts:646`)** to eight panels, in the new order.

**§4.1c mutations** (`scripts/check-cbcmac-mutations.mjs`, concrete patches with one anchor
each):

1. `spliceOne` returns `m ‖ m` (the `⊕ t` dropped) → the forgery test fails.
2. `verifyAnyLength` gains a length check → the vulnerable-acceptance claim fails.
3. `prependLengthCbcMac` drops the length block → "prepended rejects the forgery" fails.
4. The ALARM chip on an accepted forgery is styled calm → the verdict-class claim fails.
5. `cmacBytes` uses K2 for a complete final block → RFC 4493 Example 2 or 4 fails.

**§4.1d negative claim:** *"A valid raw CBC-MAC tag does not authenticate the message's length:
when the receiver accepts more than one length, every check this verifier performs passes on a
message nobody tagged."*

- **Fixture:** after "Forge", the vulnerable verifier renders `TAG VALID — AND FORGED`. The
  page's only checks in that card are tag equality and block alignment, and both pass.
- The sentence is visible in that state. Assert all three §4.1d points, and confirm mutation 1
  breaks the fixture.

## README and card follow-up

- **What It Is:** add raw CBC-MAC and the reason CMAC exists.
- **Exhibits** (`README.md:11–21`): insert "Raw CBC-MAC — fixed length only" before CMAC and
  renumber.
- **Tests:** add the new vectors with their sources and the second mutation script.
- **Catalog handoff (do not edit `../crypto-lab`):** proposed chip `CBC-MAC Forgery` (implemented
  and executed). The existing four chips stay.

## Do not touch

The CRC lesson and its mutation script, the HMAC/Poly1305/GHASH/timing panels, the passphrase
behaviour of `computeCmac`, the theme pin and the header.

## Sources

- Katz, Lindell. *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369) — §4.4.1, Construction 4.9, Theorem 4.10, Figure 4.2, Exercises 4.13–4.15; the
  book's reference [191] for CMAC is RFC 4493. Checked against the book's text.
- M. Bellare, J. Kilian, P. Rogaway. "The Security of the Cipher Block Chaining Message
  Authentication Code." *Journal of Computer and System Sciences* 61(3):362–399, 2000.
  doi:10.1006/jcss.1999.1694 (Crossref).
- J. H. Song, R. Poovendran, J. Lee, T. Iwata. RFC 4493, "The AES-CMAC Algorithm", June 2006 —
  §4 test vectors (RFC Editor text).
- M. Dworkin. NIST SP 800-38B, *Recommendation for Block Cipher Modes of Operation: The CMAC Mode
  for Authentication*, May 2005, updated 10/6/2016 (CSRC publication page).
- NIST CSRC, "Examples with Intermediate Values", `AES_CMAC.pdf` — the AES-256 tags quoted above.
- M. Dworkin. NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation: Methods and
  Techniques*, December 2001 — Appendix F.1.1, F.1.5 and F.2.1 values quoted above (read from
  nvlpubs.nist.gov).
