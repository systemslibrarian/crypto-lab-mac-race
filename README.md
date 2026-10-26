# crypto-lab-mac-race

Primitives: CRC-32/ISO-HDLC · HMAC-SHA-256 · HMAC-SHA-512 · Raw CBC-MAC · AES-CMAC · PMAC (Black–Rogaway 2002) · Poly1305 · GHASH

## What It Is

crypto-lab-mac-race is a browser demo for CRC-32, HMAC-SHA-256, HMAC-SHA-512, raw CBC-MAC, AES-CMAC, the 2002 Black–Rogaway PMAC, and Poly1305, plus GHASH and attack panels that show where incorrect authentication constructions fail. CRC-32 is an unkeyed checksum for accidental corruption; the MACs use shared secret material to verify message integrity and origin authenticity. None of these mechanisms encrypt plaintext. The project shows how each construction behaves under correct and incorrect usage, including checksum repair, block-position and final-rule changes, nonce/key reuse, length extension on a vulnerable prefix-MAC pattern, and timing leakage from naive comparison.

A newcomer starts at a "What is a MAC?" intro card — a one-sentence framing plus a small animation of a message and secret key flowing into a fixed-size tag, and an attacker who alters the message getting rejected — so the mental model is grounded before any primitive appears. A guided tour then walks the panels in pedagogical order. Field-math mechanisms are shown as pictures, not just hex: the GHASH panel animates `T1 ⊕ T2 = (C1 ⊕ C2)·H` as stacked 128-bit bit-rows showing the shared `·H` factor remains after XOR; this raw-field toy omits GCM framing and its nonce mask, and the length-extension panel draws the forged message as labelled `[secret][message][glue padding][append]` segments with the secret greyed as unknown. First-use jargon (ipad/opad, Merkle-Damgard, clamped r, GF(2^128), FIPS 198-1) carries inline hover/focus definitions.

## Exhibits

The intro card defines a MAC and shows a message and key flowing into a tag. The guided tour covers nine lessons:

1. **Checksum vs MAC** — CRC-32 catches flipped bits and a naive tamper, then accepts a repaired checksum or four-byte forced target. HMAC-SHA-256 rejects the same changed message until the optional key-leak toggle is enabled.
2. **HMAC** (the safe default) — step-through of the ipad/opad nested construction, an avalanche bit-diff grid with a "why ~50% flip matters" security note, and a server verifier.
3. **Length-extension attack** — capture a `SHA-256(secret ∥ msg)` tag, forge an extended tag without the secret, and see a labelled diagram of the forged message layout; a side-by-side HMAC server rejects the same attack.
4. **Raw CBC-MAC — fixed length only** — get one or two real tags, construct a longer message without the key, then compare the vulnerable receiver with agreed-length, length-prepended and CMAC checks. The trace shows the exact chain cancellation that motivates CMAC.
5. **CMAC** — NIST SP 800-38B subkey (K1/K2) derivation and final-block handling, step-by-step.
6. **PMAC** — execute the exact byte-aligned, full-tag Black–Rogaway 2002 construction with AES-256, inspect its Gray-code offsets and independent AES inputs, mutate content/position/final-block treatment, and compare its AES dependency graph with CMAC. The scheduling view models AES calls; it is not a speed benchmark.
7. **Poly1305** (one-time only) — reuse the one-time key across two messages to recover `r` and forge a tag, with a disclosed teaching simplification of the search size (the algebra is real and runs live).
8. **GHASH** — ordinary computation includes the ciphertext length block with no AAD, but returns an unmasked hash, not a GCM tag. A separate raw single-block `T=C·H` toy visualizes fixed-H linearity. It has no nonce, length block or authentication mask and its verifier is not a real GCM endpoint.
9. **MAC comparison + timing attack** — a primitive comparison table and a byte-by-byte tag recovery driven by a non-constant-time compare, with an on-screen banner disclosing that the oracle reports match-length directly as an honest stand-in for averaged timing.

## When to Use It

- Use HMAC-SHA-256 or HMAC-SHA-512 for API request signing and token integrity because HMAC is designed to resist Merkle-Damgard length extension that breaks bare prefix-hash MACs.
- Use AES-CMAC in NIST/FIPS-oriented environments because it provides a standardized block-cipher-based MAC when AES primitives are already required.
- Use the PMAC lesson to study a parallelizable block-cipher MAC because its independently offset non-final AES calls expose a different dependency graph from CMAC; do not infer NIST standardization or deployment guidance from this historical construction.
- Use Poly1305 only as a one-time authenticator key schedule (typically ChaCha20-derived) because reusing its one-time key enables practical forgeries.
- Use GHASH only inside correctly implemented AES-GCM with strict nonce discipline because GHASH linearity makes nonce reuse catastrophic for integrity.
- Do not use this set of primitives as a substitute for public-key signatures when third-party verifiability is required because all listed MAC constructions are symmetric and require shared secrets.
- Do NOT use this as production code — it is a teaching demo that includes deliberately vulnerable constructions for illustration, not a hardened MAC library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/)**

The demo lets you run nine interactive panels: Checksum vs MAC, HMAC, Raw CBC-MAC, CMAC, PMAC, Poly1305, GHASH, a SHA-256 length-extension attack, and a timing-attack comparison for naive vs constant-time verification. You can edit messages and attack inputs, then recompute outputs to observe how checksums, tags, dependency schedules, and attack outcomes change. It does not provide encrypt/decrypt workflows; it is focused on message authentication behavior and misuse demonstrations.

## What Can Go Wrong

- Raw CBC-MAC accepts a spliced longer message when lengths are unrestricted. An agreed-length receiver must share that restriction with its sender. The length-prepended and CMAC controls also test the recipe against their own oracles; they use separate keys, because exposing raw CBC-MAC under a CMAC key creates a different cross-protocol attack.
- Prefix-MAC length extension with bare SHA-256(secret || message): an attacker can forge a valid MAC for extended data without knowing the secret, which is demonstrated in the length-extension panel.
- Poly1305 one-time key reuse breaks message authenticity. The in-app demo narrows `r` to 16 bits for simple classroom brute force, not because full-size single-block reuse is intractable. For known single-block messages, reduction modulo 2^130−5 removes the large pre-reduction quotient, leaving a small number of tag-truncation carry candidates; an additional observation may be needed to distinguish them. Two tags do not universally identify one key, and arbitrary multi-block cases have different polynomial equations. The displayed forgery is checked by the real authenticator with the deliberately narrowed key. See [RFC 8439 §2.5](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5).
- Real GCM uses padded AAD/ciphertext, the mandatory length block and the nonce-derived mask `E_K(J0)` (NIST SP 800-38D algorithms 4/5). `H=E_K(0^128)` stays the same for a fixed key even across distinct nonces. With equal-length one-block ciphertexts, no AAD and full tags under one key/nonce, tag differences involve `H²`, not the toy's `H`. Local toy acceptance does not demonstrate a real GCM forgery.
- GHASH nonce reuse in GCM contexts: because GHASH is linear over GF(2^128), nonce reuse can expose relationships that permit forgery and broader AEAD failure.
- Non-constant-time MAC comparison: byte-by-byte early-exit checks leak timing information that helps attackers recover or validate tag bytes incrementally.
- CMAC implementation mistakes (subkey/padding/final-block handling): incorrect K1/K2 derivation or final block processing can produce incompatible or insecure tags.
- PMAC implementation mistakes can break interoperability or authenticity if the Gray-code offset recurrence, block position, 10* padding, or complete-final-block `L·x^-1` adjustment changes. This lab pins the 2002 construction rather than silently mixing in later PMAC refinements.
- A PMAC dependency span is not a runtime speedup claim. The model counts AES scheduling waves under a selected lane limit and excludes XOR, offset preparation, API overhead, hardware scheduling, and cached per-key setup.
- PMAC's post-quantum status depends on the oracle model. This lesson permits ordinary classical MAC queries. Kaplan, Leurent, Leverrier and Naya-Plasencia give a Simon-style forgery with quantum-superposition (Q2) oracle access, so the 2002 construction is not Q2-secure; this lab does not implement that stronger oracle. See [*Breaking Symmetric Cryptosystems Using Quantum Period Finding*](https://arxiv.org/abs/1602.05973).

## Real-World Usage

- TLS 1.2 record protection and PRF: HMAC-based constructions are used for record authentication and key-derivation components in legacy TLS suites.
- AWS Signature Version 4: request authentication uses chained HMAC-SHA-256 derivations to bind credentials, date scope, and canonical request data.
- ChaCha20-Poly1305 in TLS 1.3 and QUIC: Poly1305 is used as the authenticator in the AEAD construction with per-record nonce/key derivation.
- AES-GCM in TLS/IPsec: GHASH is the authentication polynomial component inside GCM tag generation and verification.
- 3GPP LTE EIA2 integrity algorithm: AES-CMAC is used to authenticate signaling messages in mobile network protocols.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-mac-race
cd crypto-lab-mac-race
npm install
npm run dev
```

## Tests

Correctness is gated by a runnable unit suite (Vitest), not just the in-browser
self-tests:

```bash
npm test        # KAT / property / forgery-rejection unit tests
npx playwright install chromium firefox webkit
npm run test:a11y  # browser gate (Playwright): on-screen claims + axe-core WCAG A/AA
npm run test:mutations  # original eight CRC/HMAC faults, unchanged
npm run test:mutations:cbcmac  # six raw-CBC-MAC / CMAC faults
npm run test:mutations:pmac  # ten PMAC arithmetic / verifier / model / boundary faults
```

The suite covers CRC-32/ISO-HDLC check and residue vectors, fixed-seed checksum repairs and four-byte target forcing through the real receiver, RFC 4231 HMAC vectors, NIST SP 800-38B AES-CMAC, RFC 8439
Poly1305, GHASH GF(2^128) vectors and field laws, the from-scratch SHA-256
core cross-checked against WebCrypto, and bounded local demonstrations: the raw
GHASH toy recovers a live-derived `H` and checks another raw field product.
This is not AES-GCM acceptance; genuine WebCrypto GCM verification controls accept
a published tag and reject the toy product and unmasked GHASH output; the length-extension forgery is verified against a
full re-hash and rejected on a wrong length guess; the Poly1305 reuse forgery
must match the tag the real key produces. PMAC is checked against the authors'
published AES-128 and AES-256 vectors (including the 1,000-byte cases) and an
independent noble-AES/BigInt implementation across every byte length from 0 to
257. The implementation follows [Black and Rogaway, EUROCRYPT 2002, §§2–5](https://www.cs.ucdavis.edu/~rogaway/papers/pmac.pdf);
the author-hosted [AES-128](https://www.cs.ucdavis.edu/~rogaway/ocb/pmac128.txt)
and [AES-256](https://www.cs.ucdavis.edu/~rogaway/ocb/pmac256.txt) vector files
are the known-answer sources. The later 2004 refinements are not substituted.

`e2e/claims.spec.ts` gates the *page* on the same standard: it independently recomputes every displayed CRC from the displayed bytes, checks the affine equation and HMAC control, and drives the real
panels and re-derives each verdict from what the page printed — the HMAC tag
against its own step list, the bit-diff labels against the cells they drew, the
GHASH deltas against the ciphertexts and tags beside them, the timing summary
against the rows above it — and sweeps the attacker's whole 8..24-byte secret
length search space, asserting exactly one guess forges a tag the broken server
accepts while the HMAC server rejects every one. The browser gate scans the
dark-only page at desktop and phone widths in Chromium, and checks the core lesson in
Firefox and WebKit. The unit, browser, and mutation gates run in CI before
every Pages deploy.

`e2e/pmac.spec.ts` reads the run's disclosed public teaching keys and recomputes
every displayed PMAC and CMAC tag with noble AES and independent BigInt field
arithmetic. It checks every lane's block, offset, AES input and AES output, both
final-block rules, content and position mutations, dependency spans, result
retirement, delayed obsolete work, and the variant/standardization/performance
boundaries. Disclosing those random teaching keys makes the trace auditable; it
is not an attacker model or an authenticity deployment.

The raw-CBC-MAC extension adds 19 unit tests (85 total). The byte-level CMAC
API preserves the existing string/passphrase-to-AES-256 behavior and permits
exact AES-128/256 vectors through the original WebCrypto block path. Pins:

- NIST SP 800-38A F.1.1/F.1.5 first AES-128/256 ECB blocks.
- RFC 4493 §4: all four AES-128 CMAC examples (0, 16, **40**, 64 bytes) and both subkeys.
- NIST CSRC `AES_CMAC.pdf`: all four AES-256 examples (0, 16, **20**, 64 bytes).
  The 2016 SP 800-38B update moved its former Appendix D examples to CSRC;
  the old test comment is re-anchored to that actual file.
- A **derived** raw-CBC-MAC check: fold SP 800-38A F.2.1’s IV into its first
  plaintext block, then compare the zero-IV MAC with the published last CBC
  ciphertext. This is not a published CBC-MAC vector.

Independent noble AES/CMAC checks cover 100 random 1–8-block raw chains and
all message lengths 0–100. One- and two-query algebra is tested for 100 random
keys, including the own-CMAC-oracle control. Another independent regression
pins the shared-key cross-protocol caveat, so the comparison cannot silently
reintroduce it. Shipping crypto does not call noble.

Five browser claims reconstruct forged bytes from printed messages/tags, check
actual aligned chain convergence and every verdict cause/style, exercise the
negative claim, UTF-8, general splices, mismatched sender/receiver lengths,
no-op preservation, retirement and delayed AES completions. The tour has nine
steps. Accessibility walks include the new states at desktop, 380px and 320px.
`cbcmac-mutation-evidence.json` records actual patches, successful changed builds,
named zero-retry assertion failures, exact restoration and passing owning tests.
Browser mutation runs verify served-JavaScript identity. The original CRC
mutation runner is unchanged.

The PMAC extension adds 21 unit tests (106 total), five browser claim tests and
a ten-case zero-retry mutation gate. `pmac-mutation-evidence.json` records the
concrete patches, owning assertion failures, served-asset guard and exact clean
restoration. CI runs the original CRC/HMAC, raw-CBC-MAC/CMAC and PMAC mutation
gates before deployment.

## Related Demos

- [crypto-lab-poly1305-mac](https://systemslibrarian.github.io/crypto-lab-poly1305-mac/) — deep dive on the Poly1305 polynomial authenticator and its key-reuse attack.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — shows how GHASH/AES-GCM fails under nonce reuse.
- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — the SHA-2/SHA-3/BLAKE3 hash internals that HMAC is built on.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — Merkle-Damgard construction behind length-extension.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AEAD and block-cipher modes that consume these MACs.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
