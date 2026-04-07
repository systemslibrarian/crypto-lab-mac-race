# crypto-lab-mac-race

Live demo: https://systemslibrarian.github.io/crypto-lab-mac-race/

Primitives: HMAC-SHA-256 · HMAC-SHA-512 · AES-CMAC · Poly1305 · GHASH

## Overview

crypto-lab-mac-race is a browser-based interactive demonstration of Message Authentication Codes (MACs):

- HMAC (FIPS 198-1)
- AES-CMAC (NIST SP 800-38B)
- Poly1305 (RFC 8439)
- GHASH (NIST SP 800-38D / GCM authentication component)

The demo compares construction, performance, security properties, and failure modes, including:

- Real SHA-256 length extension against a vulnerable prefix-MAC construction.
- Timing leaks from naive MAC comparison versus constant-time comparison.

## MACs Covered

- Panel 1: HMAC-SHA-256 and HMAC-SHA-512 via WebCrypto `SubtleCrypto.sign`
- Panel 2: AES-256-CMAC with exact SP 800-38B subkey generation and padding
- Panel 3: Poly1305 with one-time key requirements and key-reuse warning demo
- Panel 4: GHASH polynomial hashing and nonce/key-reuse risk explanation
- Panel 5: Length extension attack on `SHA-256(secret || message)`
- Panel 6: Side-by-side MAC comparison and timing attack measurement

## Primitives Used

- WebCrypto API:
	- HMAC-SHA-256 / HMAC-SHA-512 signing
	- AES-CBC single-block encryption used as AES-ECB primitive for CMAC internals
- @noble/ciphers:
	- Poly1305
	- GHASH helpers/utilities integration
- Native browser timing:
	- `performance.now()` for measurable timing-leak demonstrations

## Running Locally

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
```

Deploy to GitHub Pages:

```bash
npm run deploy
```

## Security Notes

- Never use a bare hash as a MAC (`SHA-256(secret || message)` is vulnerable to length extension).
- Never reuse a Poly1305 one-time key.
- Never reuse a GCM nonce (GHASH-related breakage can follow).
- Always verify MACs with constant-time comparison.

## Accessibility

WCAG 2.1 AA goals in this project:

- Keyboard navigation throughout all interactive controls.
- Screen-reader navigable panel structure with ARIA labels and live status messages.
- Visible focus indicators in dark and light modes.
- Color + text status indicators (never color alone).
- Reduced motion support via `prefers-reduced-motion`.

## Why This Matters

MAC failure remains one of the most common causes of real-world cryptographic vulnerabilities. Timing side channels and construction misuse have both broken production systems repeatedly.

## Related Demos

- crypto-lab landing page: https://systemslibrarian.github.io/crypto-lab/
- crypto-lab-aes-modes: https://systemslibrarian.github.io/crypto-lab-aes-modes/
- crypto-lab-shadow-vault: https://systemslibrarian.github.io/crypto-lab-shadow-vault/
- crypto-lab-babel-hash: https://systemslibrarian.github.io/crypto-lab-babel-hash/
- crypto-compare: https://systemslibrarian.github.io/crypto-compare/

So whether you eat or drink or whatever you do, do it all for the glory of God. -- 1 Corinthians 10:31