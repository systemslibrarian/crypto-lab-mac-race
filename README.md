# crypto-lab-mac-race

Primitives: HMAC-SHA-256 · HMAC-SHA-512 · AES-CMAC · Poly1305 · GHASH

## What It Is

crypto-lab-mac-race is a browser demo for HMAC-SHA-256, HMAC-SHA-512, AES-CMAC, Poly1305, and GHASH, plus attack panels that show where incorrect MAC constructions fail. These primitives are symmetric-key authentication mechanisms used to verify message integrity and origin authenticity, not to encrypt plaintext. The project focuses on how each construction behaves under correct and incorrect usage, including nonce/key reuse, length extension on a vulnerable prefix-MAC pattern, and timing leakage from naive comparison. The security model is symmetric authentication with shared secret material between parties.

## When to Use It

- Use HMAC-SHA-256 or HMAC-SHA-512 for API request signing and token integrity because HMAC is designed to resist Merkle-Damgard length extension that breaks bare prefix-hash MACs.
- Use AES-CMAC in NIST/FIPS-oriented environments because it provides a standardized block-cipher-based MAC when AES primitives are already required.
- Use Poly1305 only as a one-time authenticator key schedule (typically ChaCha20-derived) because reusing its one-time key enables practical forgeries.
- Use GHASH only inside correctly implemented AES-GCM with strict nonce discipline because GHASH linearity makes nonce reuse catastrophic for integrity.
- Do not use this set of primitives as a substitute for public-key signatures when third-party verifiability is required because all listed MAC constructions are symmetric and require shared secrets.
- Do NOT use this as production code — it is a teaching demo that includes deliberately vulnerable constructions for illustration, not a hardened MAC library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/)**

The demo lets you run six interactive panels: HMAC, CMAC, Poly1305, GHASH, a SHA-256 length-extension attack, and a timing-attack comparison for naive vs constant-time verification. You can edit message, key, ciphertext, and attacker-append inputs, then recompute outputs to observe how tags and attack outcomes change. It does not provide encrypt/decrypt workflows; it is focused on message authentication behavior and misuse demonstrations.

## What Can Go Wrong

- Prefix-MAC length extension with bare SHA-256(secret || message): an attacker can forge a valid MAC for extended data without knowing the secret, which is demonstrated in the length-extension panel.
- Poly1305 one-time key reuse: reusing the same one-time key across messages turns two tags into linear equations in the key element `r`, which breaks message authenticity. (The in-app attack narrows `r` to a 16-bit search so the algebra runs live in the browser — this is a disclosed teaching simplification of the search size; recovering full ~106-bit `r` from only two tags is not tractable because each single-block accumulator is reduced mod 2^130−5.)
- GHASH nonce reuse in GCM contexts: because GHASH is linear over GF(2^128), nonce reuse can expose relationships that permit forgery and broader AEAD failure.
- Non-constant-time MAC comparison: byte-by-byte early-exit checks leak timing information that helps attackers recover or validate tag bytes incrementally.
- CMAC implementation mistakes (subkey/padding/final-block handling): incorrect K1/K2 derivation or final block processing can produce incompatible or insecure tags.

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
npm run test:a11y  # axe-core WCAG A/AA gate (Playwright)
```

The suite covers RFC 4231 HMAC vectors, NIST SP 800-38B AES-CMAC, RFC 8439
Poly1305, GHASH GF(2^128) vectors and field laws, the from-scratch SHA-256
core cross-checked against WebCrypto, and each attack end-to-end: the GHASH
Forbidden Attack recovers a live-derived `H` and the "server" (holding the true
`H`) confirms the forgery; the length-extension forgery is verified against a
full re-hash and rejected on a wrong length guess; the Poly1305 reuse forgery
must match the tag the real key produces. Both `npm test` and the a11y gate run
in CI before every Pages deploy.

## Related Demos

- [crypto-lab-poly1305-mac](https://systemslibrarian.github.io/crypto-lab-poly1305-mac/) — deep dive on the Poly1305 polynomial authenticator and its key-reuse attack.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — shows how GHASH/AES-GCM fails under nonce reuse.
- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — the SHA-2/SHA-3/BLAKE3 hash internals that HMAC is built on.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — Merkle-Damgard construction behind length-extension.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AEAD and block-cipher modes that consume these MACs.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
