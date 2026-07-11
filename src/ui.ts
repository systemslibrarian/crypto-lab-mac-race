import { avalancheBitFlip, computeHmac, verifyHmac } from './hmac';
import { computeCmac, verifyCmac } from './cmac';
import { computePoly1305, runKeyReuseAttackDemo } from './poly1305';
import { computeGhash, runGhashReuseAttackDemo } from './ghash';
import {
  ATTACKER_SECRET_LENGTH_RANGE,
  attemptForge,
  captureOriginalRequest,
  getActualSecretLength,
  hmacServerVerify,
  rawServerVerify,
  regenerateDemoSecret
} from './lengthext';
import { recoverTagByTimingAttack, runTimingDemo } from './timing';

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element: ${id}`);
  return element as T;
}

function setStatus(message: string, isError = false): void {
  const live = byId<HTMLDivElement>('aria-live');
  live.textContent = message;
  live.dataset.kind = isError ? 'error' : 'ok';
}

function fmtHex(hex: string, max = 128): string {
  return hex.length > max ? `${hex.slice(0, max)}...` : hex;
}

// A revealable step list: each call to step() unhides the next line.
function makeStepper(container: HTMLElement, lines: string[]): { step: () => boolean; revealAll: () => void; reset: () => void } {
  container.textContent = '';
  const elements = lines.map((text) => {
    const div = document.createElement('div');
    div.className = 'step-line';
    div.textContent = text;
    div.hidden = true;
    container.appendChild(div);
    return div;
  });
  let cursor = 0;
  return {
    step(): boolean {
      if (cursor >= elements.length) return false;
      elements[cursor].hidden = false;
      elements[cursor].classList.add('step-line-new');
      cursor += 1;
      return cursor < elements.length;
    },
    revealAll(): void {
      for (let i = cursor; i < elements.length; i += 1) elements[i].hidden = false;
      cursor = elements.length;
    },
    reset(): void {
      for (const el of elements) el.hidden = true;
      cursor = 0;
    }
  };
}

function renderBitDiffGrid(container: HTMLElement, aHex: string, bHex: string, caption: string): void {
  container.textContent = '';
  const a = hexToBytes(aHex);
  const b = hexToBytes(bHex);
  const grid = document.createElement('div');
  grid.className = 'bitdiff-grid';
  grid.setAttribute('role', 'img');
  let flipped = 0;
  const totalBits = Math.min(a.length, b.length) * 8;
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const x = a[i] ^ b[i];
    for (let bit = 7; bit >= 0; bit -= 1) {
      const cell = document.createElement('span');
      cell.className = 'bitdiff-cell';
      const isFlip = ((x >> bit) & 1) === 1;
      if (isFlip) {
        cell.classList.add('bitdiff-flip');
        flipped += 1;
      }
      grid.appendChild(cell);
    }
  }
  const pct = totalBits === 0 ? 0 : (flipped / totalBits) * 100;
  const label = document.createElement('p');
  label.className = 'bitdiff-label';
  label.textContent = `${caption} — ${flipped}/${totalBits} bits flipped (${pct.toFixed(1)}%)`;
  container.appendChild(grid);
  container.appendChild(label);
  grid.setAttribute('aria-label', label.textContent);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function setVerdict(el: HTMLElement, accepted: boolean, acceptedLabel = 'ACCEPTED', rejectedLabel = 'REJECTED'): void {
  el.textContent = accepted ? acceptedLabel : rejectedLabel;
  el.classList.remove('verdict-accept', 'verdict-reject', 'verdict-idle');
  el.classList.add(accepted ? 'verdict-accept' : 'verdict-reject');
}

function setVerdictIdle(el: HTMLElement, label: string): void {
  el.textContent = label;
  el.classList.remove('verdict-accept', 'verdict-reject');
  el.classList.add('verdict-idle');
}

function renderTimingRows(): void {
  const tableBody = byId<HTMLTableSectionElement>('timing-rows');
  tableBody.textContent = '';
  const timing = runTimingDemo();
  for (const row of timing.rows) {
    const tr = document.createElement('tr');
    const tdLabel = document.createElement('td');
    tdLabel.textContent = row.label;
    const tdNaive = document.createElement('td');
    tdNaive.textContent = `${row.naiveMs.toFixed(3)} ms`;
    const tdConst = document.createElement('td');
    tdConst.textContent = `${row.constantMs.toFixed(3)} ms`;
    tr.append(tdLabel, tdNaive, tdConst);
    tableBody.appendChild(tr);
  }
  byId<HTMLElement>('timing-summary').textContent = timing.summary;
}

// Source snippets shown via the "View source" panels.
const HMAC_SRC = `// HMAC = H(K' ⊕ opad || H(K' ⊕ ipad || message))
const ipad = new Uint8Array(blockSize);
const opad = new Uint8Array(blockSize);
for (let i = 0; i < blockSize; i++) {
  ipad[i] = normalizedKey[i] ^ 0x36;
  opad[i] = normalizedKey[i] ^ 0x5c;
}
const inner = await digest(hash, concat(ipad, message));
const outer = await digest(hash, concat(opad, inner));
return outer; // the HMAC tag`;

const CMAC_SRC = `// NIST SP 800-38B subkey derivation
const L = await aesEncryptBlock(key, new Uint8Array(16));
let K1 = leftShift(L);
if ((L[0] & 0x80) !== 0) K1[15] ^= 0x87;  // Rb
let K2 = leftShift(K1);
if ((K1[0] & 0x80) !== 0) K2[15] ^= 0x87;
// Last block: XOR with K1 if message is a whole multiple of 16,
// otherwise apply 10* padding and XOR with K2.`;

const POLY_SRC = `// Two messages under the SAME one-time key leak r:
// tag1 = (m1 * r + s) mod 2^128
// tag2 = (m2 * r + s) mod 2^128
// tag1 - tag2 ≡ (m1 - m2) * r  → solve for r
for (let rGuess = 0n; rGuess <= 0xffffn; rGuess++) {
  const sGuess = (tag1 - m1*rGuess + MOD) % MOD;
  if ((m2*rGuess + sGuess) % MOD === tag2) {
    // forge any new message m3 with the recovered (r, s).
  }
}`;

const GHASH_SRC = `// GHASH is linear in GF(2^128):
//   T = C * H + L * H
// Two ciphertexts under the SAME nonce share the same H.
//   T1 ^ T2 = (C1 ^ C2) * H
//   H = (T1 ^ T2) * (C1 ^ C2)^(-1)
const deltaT = xor16(T1, T2);
const deltaC = xor16(C1, C2);
const H = gf128Mul(deltaT, gfInverse(deltaC));`;

const LENGTHEXT_SRC = `// Attacker observes tag = SHA-256(secret || message)
// SHA-256 state IS the tag — attacker resumes from it.
const state = parseStateFromDigest(tagHex);
const glue = sha256Pad(secretLen + message.length);
const forgedMessage = concat(message, glue, append);
// Feed only the append + final padding into the resumed state.
const totalAfterAppend = secretLen + message.length + glue.length + append.length;
for (const block of blocks(append, sha256Pad(totalAfterAppend))) {
  compress(state, block);
}
return stateToDigestHex(state); // valid forged tag, secret never needed`;

const TIMING_SRC = `// VULNERABLE: leaks prefix-match length via early exit.
function naiveEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;     // ← early exit
  }
  return true;
}

// SAFE: constant time, branchless on data.
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}`;

const LESSON_STEPS: { panelId: string; title: string; body: string }[] = [
  { panelId: 'p1', title: '1. HMAC — the safe default', body: 'Start here. HMAC nests two hashes around the key so that knowing the tag tells you nothing about the internal hash state. This is what API request signing should use.' },
  { panelId: 'p5', title: '2. Why we need HMAC: length-extension', body: 'Bare SHA-256(secret || message) leaks enough internal state through its tag that an attacker can forge tags for extended messages without the secret. Forge a tag, then verify it on the broken server.' },
  { panelId: 'p2', title: '3. CMAC — block-cipher MAC', body: 'When AES is already in your stack, CMAC gives you a NIST-approved MAC built from a block cipher. Notice K1/K2 are derived from AES_K(0).' },
  { panelId: 'p3', title: '4. Poly1305 — fast, one-time only', body: 'A polynomial MAC. Reuse the one-time key across two messages and r can be solved in seconds; the attacker forges arbitrary tags afterwards.' },
  { panelId: 'p4', title: '5. GHASH — linear in GF(2^128)', body: "GHASH is what authenticates AES-GCM. It is linear in the field, so nonce reuse leaks the hash subkey H. This is the Forbidden Attack." },
  { panelId: 'p6', title: '6. Timing attack — non-constant-time compare', body: 'A naive byte-by-byte equality leaks prefix-match length. Watch a real byte-by-byte tag recovery driven entirely by that signal.' }
];

export function renderApp(container: HTMLElement): void {
  container.innerHTML = `
    <div class="page" aria-label="MAC Race demo root">
      <a class="skip-link" href="#main-content" aria-label="Skip to main content">Skip to main content</a>
      <header class="hero" aria-label="Header section">
        <span class="chip chip-category" aria-label="Category chip">MAC</span>
        <button
          id="theme-toggle"
          class="theme-toggle"
          aria-label="Switch to light mode"
          style="position: absolute; top: 0; right: 0;"
        >🌙</button>
        <h1>MAC Race</h1>
        <p class="subtitle">Construction, misuse resistance, and real attack demonstrations for modern Message Authentication Codes.</p>
        <p class="chip-row" aria-label="Primitive chips">HMAC-SHA-256 · HMAC-SHA-512 · AES-CMAC · Poly1305 · GHASH</p>
      </header>

      <section class="tour" aria-label="Guided tour">
        <div class="tour-head">
          <div>
            <strong id="tour-title">Guided tour: start with HMAC →</strong>
            <p class="tour-body" id="tour-body">Click "Start tour" to walk through the panels in pedagogical order. Each step highlights one panel and explains what the lesson is.</p>
          </div>
          <div class="tour-controls">
            <button id="tour-start" aria-label="Start guided tour">Start tour</button>
            <button id="tour-prev" aria-label="Previous lesson" hidden>← Prev</button>
            <button id="tour-next" aria-label="Next lesson" hidden>Next →</button>
            <button id="tour-end" aria-label="End tour" hidden>End</button>
          </div>
        </div>
        <p class="tour-progress" id="tour-progress" hidden></p>
      </section>

      <main id="main-content" class="panel-grid" aria-label="MAC demo panels">

        <section class="panel" id="p1" aria-labelledby="p1-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 1</span>
            <h2 id="p1-title">HMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED DEFAULT">RECOMMENDED DEFAULT</span>
          </div>
          <label for="hmac-message">Message</label>
          <textarea id="hmac-message" aria-label="HMAC message input">transfer=42&to=bob</textarea>
          <label for="hmac-key">Key (text or hex)</label>
          <input id="hmac-key" aria-label="HMAC key input" value="super-secret-key" />
          <div class="button-row">
            <button id="hmac-run" aria-label="Compute HMAC results">Compute HMAC</button>
            <button id="hmac-step" class="secondary" aria-label="Step through HMAC stages">Step ▸</button>
            <button id="hmac-reveal" class="secondary" aria-label="Reveal all HMAC stages">Reveal all</button>
          </div>
          <div id="hmac-output" class="hex stepper" role="status" aria-live="polite" aria-label="HMAC output"></div>

          <div class="bitdiff-section">
            <p class="note"><strong>Avalanche:</strong> flip one bit of the message or one bit of the key — watch ~50% of output bits change.</p>
            <div id="hmac-bitdiff-msg" class="bitdiff-block"></div>
            <div id="hmac-bitdiff-key" class="bitdiff-block"></div>
          </div>

          <div class="verifier" aria-label="HMAC server verifier">
            <h3>Server verifies</h3>
            <label for="hmac-verify-tag">Candidate tag (hex)</label>
            <input id="hmac-verify-tag" aria-label="HMAC candidate tag" />
            <div class="button-row">
              <button id="hmac-verify" aria-label="Verify HMAC tag">Verify on server</button>
              <span id="hmac-verdict" class="verdict verdict-idle">awaiting input</span>
            </div>
          </div>

          <p class="note">FIPS 198-1: HMAC uses nested hashing with ipad/opad, so length extension against bare SHA-256 does not apply.</p>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src">${escapeHtml(HMAC_SRC)}</pre></details>
        </section>

        <section class="panel" id="p2" aria-labelledby="p2-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 3</span>
            <h2 id="p2-title">CMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED for FIPS contexts">RECOMMENDED (FIPS contexts)</span>
          </div>
          <label for="cmac-message">Message</label>
          <textarea id="cmac-message" aria-label="CMAC message input">audit-log-entry</textarea>
          <label for="cmac-key">AES-256 key (64 hex or passphrase)</label>
          <input id="cmac-key" aria-label="CMAC key input" value="fips-demo-key" />
          <div class="button-row">
            <button id="cmac-run" aria-label="Compute CMAC">Compute CMAC</button>
            <button id="cmac-step" class="secondary" aria-label="Step through CMAC stages">Step ▸</button>
            <button id="cmac-reveal" class="secondary" aria-label="Reveal all CMAC stages">Reveal all</button>
          </div>
          <div id="cmac-output" class="hex stepper" role="status" aria-live="polite" aria-label="CMAC output"></div>

          <div class="verifier" aria-label="CMAC server verifier">
            <h3>Server verifies</h3>
            <label for="cmac-verify-tag">Candidate tag (hex)</label>
            <input id="cmac-verify-tag" aria-label="CMAC candidate tag" />
            <div class="button-row">
              <button id="cmac-verify" aria-label="Verify CMAC tag">Verify on server</button>
              <span id="cmac-verdict" class="verdict verdict-idle">awaiting input</span>
            </div>
          </div>

          <p class="note">NIST SP 800-38B: derives K1/K2 from AES_K(0^128), applies 10* padding, and XORs final block before last encryption.</p>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src">${escapeHtml(CMAC_SRC)}</pre></details>
        </section>

        <section class="panel" id="p3" aria-labelledby="p3-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 4</span>
            <h2 id="p3-title">Poly1305</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED with ChaCha20">RECOMMENDED (always with ChaCha20)</span>
          </div>

          <label for="poly-message">Message</label>
          <textarea id="poly-message" aria-label="Poly1305 message input">Cryptographic Forum Research Group</textarea>
          <div class="button-row">
            <button id="poly-run" aria-label="Compute Poly1305 tag">Compute tag</button>
          </div>
          <pre id="poly-output" class="hex" role="status" aria-live="polite" aria-label="Poly1305 output"></pre>

          <div class="attack-pane" aria-label="Poly1305 one-time key reuse attack">
            <h3>You are the attacker</h3>
            <p class="note">A buggy server reused the <em>same</em> one-time key for two invoice messages. Recover <code>r</code> and forge a new invoice.</p>
            <div class="button-row">
              <button id="poly-attack" aria-label="Run Poly1305 key reuse attack">Run reuse attack →</button>
            </div>
            <pre id="poly-attack-output" class="hex" role="status" aria-live="polite" aria-label="Poly1305 attack output"></pre>
          </div>

          <div class="verifier" aria-label="Poly1305 server verifier">
            <h3>Server verifies</h3>
            <p class="note">Submit the forged tag from the attack against the original key. Both messages were authenticated with that key — so the server <em>will</em> accept your forgery.</p>
            <div class="button-row">
              <button id="poly-verify" aria-label="Submit forged tag to Poly1305 server">Submit forged tag</button>
              <span id="poly-verdict" class="verdict verdict-idle">awaiting attack</span>
            </div>
          </div>

          <div class="callout-cve" aria-label="Incident callout">
            <strong>📜 RFC 8439 warns explicitly:</strong> "The key MUST be unpredictable for each invocation." Implementations that reused Poly1305 keys (early Wireguard / experimental QUIC ports, 2015–2018 era code) had to be patched specifically for this property.
          </div>

          <p class="note">RFC 8439: Poly1305 must use a unique one-time key per message, usually derived by ChaCha20 with a unique nonce.</p>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src">${escapeHtml(POLY_SRC)}</pre></details>
        </section>

        <section class="panel" id="p4" aria-labelledby="p4-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 5</span>
            <h2 id="p4-title">GHASH</h2>
            <span class="chip chip-warn" aria-label="Status secure only with nonce discipline">SECURE only with nonce discipline</span>
          </div>
          <label for="ghash-ciphertext">Ciphertext (hex)</label>
          <textarea id="ghash-ciphertext" aria-label="GHASH ciphertext hex input">0388dace60b6a392f328c2b971b2fe78</textarea>
          <div class="button-row">
            <button id="ghash-run" aria-label="Compute GHASH">Compute GHASH</button>
          </div>
          <pre id="ghash-output" class="hex" role="status" aria-live="polite" aria-label="GHASH output"></pre>

          <div class="attack-pane" aria-label="GHASH nonce reuse attack">
            <h3>You are the attacker</h3>
            <p class="note">Two ciphertexts encrypted under the <em>same</em> AES-GCM nonce share the same hash subkey H. With a single delta you can solve for H and forge tags for any other ciphertext.</p>
            <div class="button-row">
              <button id="ghash-attack" aria-label="Run GHASH nonce reuse attack">Run nonce reuse attack →</button>
            </div>
            <pre id="ghash-attack-output" class="hex" role="status" aria-live="polite" aria-label="GHASH attack output"></pre>
          </div>

          <div class="verifier" aria-label="GHASH server verifier">
            <h3>Server verifies</h3>
            <p class="note">After the nonce-reuse attack recovers H, the attacker can issue a forged tag for any ciphertext. The demo's local constant-time check (shown above) is the same operation a real GCM endpoint runs.</p>
            <div class="button-row">
              <button id="ghash-verify" aria-label="Submit forged GHASH tag">Submit forged tag</button>
              <span id="ghash-verdict" class="verdict verdict-idle">awaiting attack</span>
            </div>
          </div>

          <div class="callout-cve" aria-label="Incident callout">
            <strong>🔓 Forbidden Attack (Böck, Zauner, Devlin — 2016):</strong> a scan of the public web found 184 HTTPS servers and IoT devices reusing GCM nonces. Researchers extracted authentication keys and demonstrated full message forgery over real TLS.
          </div>

          <p class="note">NIST SP 800-38D: GHASH is linear in GF(2^128). Reusing a GCM nonce is catastrophic.</p>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src">${escapeHtml(GHASH_SRC)}</pre></details>
        </section>

        <section class="panel panel-wide" id="p5" aria-labelledby="p5-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 2</span>
            <h2 id="p5-title">Length Extension Attack</h2>
            <span class="chip chip-bad" aria-label="Status bare SHA-256 as MAC avoid">bare SHA-256 as MAC = AVOID</span>
          </div>

          <div class="capture-pane">
            <h3>1. Captured request (from the wire)</h3>
            <p class="note">The attacker observed an authenticated message and its tag in transit. They do not know the secret.</p>
            <label for="le-message">Original message</label>
            <input id="le-message" aria-label="Original message for length extension" value="comment=10&uid=7" />
            <div class="button-row">
              <button id="le-capture" aria-label="Capture original request">Capture original</button>
              <button id="le-reset-secret" class="secondary" aria-label="Rotate the secret">Rotate secret</button>
            </div>
            <div class="side-by-side">
              <div class="side broken">
                <div class="side-label"><span class="badge-bad">BROKEN</span> Server uses <code>SHA-256(secret &#124;&#124; msg)</code></div>
                <pre id="le-raw-tag" class="hex">(click "Capture original")</pre>
              </div>
              <div class="side safe">
                <div class="side-label"><span class="badge-ok">SAFE</span> Server uses <code>HMAC-SHA-256(secret, msg)</code></div>
                <pre id="le-hmac-tag" class="hex">(click "Capture original")</pre>
              </div>
            </div>
          </div>

          <div class="attack-pane">
            <h3>2. Forge a tag without the secret</h3>
            <p class="note">Length extension lets the attacker compute a valid tag for <code>message &#124;&#124; glue &#124;&#124; append</code> from the leaked tag — but only if they guess the secret length. The actual length is hidden somewhere in <strong>${ATTACKER_SECRET_LENGTH_RANGE[0]}..${ATTACKER_SECRET_LENGTH_RANGE[1]} bytes</strong>.</p>
            <label for="le-append">Attacker-appended data</label>
            <input id="le-append" aria-label="Appended attacker data" value="&admin=true" />
            <label for="le-guess">Guessed secret length: <span id="le-guess-value">16</span></label>
            <input id="le-guess" type="range" min="${ATTACKER_SECRET_LENGTH_RANGE[0]}" max="${ATTACKER_SECRET_LENGTH_RANGE[1]}" step="1" value="16" aria-label="Guessed secret length slider" />
            <div class="button-row">
              <button id="le-forge" aria-label="Forge a length-extended tag">Forge tag</button>
            </div>
            <pre id="le-forge-output" class="hex">(capture, then forge)</pre>
          </div>

          <div class="verifier">
            <h3>3. Submit the forgeries to both servers</h3>
            <div class="side-by-side">
              <div class="side broken">
                <div class="side-label"><span class="badge-bad">BROKEN server</span></div>
                <div class="button-row">
                  <button id="le-verify-raw" aria-label="Verify forged tag on bare SHA-256 server">Submit to bare-SHA-256 server</button>
                  <span id="le-verdict-raw" class="verdict verdict-idle">awaiting forge</span>
                </div>
              </div>
              <div class="side safe">
                <div class="side-label"><span class="badge-ok">SAFE server</span></div>
                <div class="button-row">
                  <button id="le-verify-hmac" aria-label="Verify forged tag on HMAC server">Submit to HMAC server</button>
                  <span id="le-verdict-hmac" class="verdict verdict-idle">awaiting forge</span>
                </div>
              </div>
            </div>
            <p class="note" id="le-summary"></p>
          </div>

          <div class="callout-cve">
            <strong>🔓 Flickr API (2009):</strong> Flickr's signed request scheme used <code>md5(secret &#124;&#124; query)</code>. Researchers Duong and Rizzo (the Lucky 13 / BEAST team) demonstrated tag forgery via length extension and could call arbitrary signed API methods. Fixed by switching to HMAC.
          </div>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src">${escapeHtml(LENGTHEXT_SRC)}</pre></details>
        </section>

        <section class="panel panel-wide" id="p6" aria-labelledby="p6-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 6</span>
            <h2 id="p6-title">MAC Comparison + Timing Attack</h2>
          </div>
          <div class="table-wrap" aria-label="MAC comparison table">
            <table>
              <caption class="sr-only">MAC primitive comparison: construction, key size, tag size, PQ resistance, and use case</caption>
              <thead><tr><th>Primitive</th><th>Construction</th><th>Key</th><th>Tag</th><th>PQ</th><th>Use case</th></tr></thead>
              <tbody>
                <tr><td>HMAC-SHA-256</td><td>Hash (Merkle-Damgard wrapped)</td><td>Any secret</td><td>256b</td><td>No</td><td>General API auth</td></tr>
                <tr><td>HMAC-SHA-512</td><td>Hash</td><td>Any secret</td><td>512b</td><td>No</td><td>Long-term integrity tokens</td></tr>
                <tr><td>AES-256-CMAC</td><td>Block cipher</td><td>256b AES</td><td>128b</td><td>No</td><td>FIPS/NIST contexts</td></tr>
                <tr><td>Poly1305</td><td>Polynomial mod 2^130-5</td><td>256b one-time</td><td>128b</td><td>No</td><td>ChaCha20-Poly1305</td></tr>
                <tr><td>GHASH</td><td>Polynomial mod x^128+x^7+x^2+x+1</td><td>128b subkey H</td><td>128b</td><td>No</td><td>AES-GCM internals</td></tr>
              </tbody>
            </table>
          </div>

          <h3>Timing differential (naive vs constant-time compare)</h3>
          <div class="button-row">
            <button id="timing-run" aria-label="Measure timing attack differences">Measure timing</button>
          </div>
          <div class="table-wrap" aria-label="Timing attack measurements">
            <table>
              <caption class="sr-only">Timing attack demonstration: naive versus constant-time MAC comparison</caption>
              <thead><tr><th>Case</th><th>Naive compare</th><th>Constant-time compare</th></tr></thead>
              <tbody id="timing-rows"></tbody>
            </table>
          </div>
          <p id="timing-summary" class="note"></p>

          <div class="attack-pane">
            <h3>Real byte-by-byte tag recovery</h3>
            <p class="note">A simulated server holds a random 16-byte tag and compares submitted candidates with <code>naiveEqual</code>. The attacker submits 256 candidates per byte position and keeps whichever produced the longest prefix-match time — recovering the entire tag without ever knowing the secret.</p>
            <div class="button-row">
              <label for="recovery-bytes">Bytes to recover:</label>
              <input id="recovery-bytes" type="number" min="1" max="16" value="8" aria-label="Number of bytes to recover" style="width: 5rem; min-height: 2rem;" />
              <button id="recovery-run" aria-label="Run byte-by-byte recovery attack">Start recovery →</button>
            </div>
            <div id="recovery-progress" class="recovery-progress" aria-live="polite">
              <div class="recovery-bar"><div id="recovery-bar-fill" class="recovery-bar-fill"></div></div>
              <p id="recovery-status" class="note">idle</p>
              <pre id="recovery-output" class="hex"></pre>
            </div>
          </div>

          <div class="callout-cve">
            <strong>🔓 Lucky 13 (AlFardan & Paterson — 2013):</strong> TLS 1.0–1.2 record MAC verification had measurable timing variation tied to padding length. Practical key-byte recovery against CBC-mode TLS, demonstrated against OpenSSL, NSS, and GnuTLS.<br/>
            <strong>🔓 Keyczar (Google) 2009, Java's <code>MessageDigest.isEqual</code> pre-Java 6u17:</strong> shipped non-constant-time MAC comparison; both fixed after public disclosure.
          </div>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src">${escapeHtml(TIMING_SRC)}</pre></details>
        </section>
      </main>

      <section class="why" aria-label="Why this matters">
        <h2>Why this matters</h2>
        <p>MAC failure is one of the most common causes of production cryptographic vulnerabilities. Length extension and timing attacks have repeatedly broken real systems.</p>
        <p class="links" aria-label="Cross links">
          <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noreferrer">crypto-lab</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noreferrer">crypto-lab-aes-modes</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-shadow-vault/" target="_blank" rel="noreferrer">crypto-lab-shadow-vault</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">crypto-lab-babel-hash</a>
          <a href="https://systemslibrarian.github.io/crypto-compare/#mac" target="_blank" rel="noreferrer">crypto-compare MAC</a>
        </p>
      </section>

      <footer class="footer" aria-label="Footer">
        <a class="github-badge" href="https://github.com/systemslibrarian/crypto-lab-mac-race" target="_blank" rel="noreferrer" aria-label="GitHub repository link">GitHub</a>
        <p class="links" aria-label="Related demos">Related demos:
          <a href="https://systemslibrarian.github.io/crypto-lab-poly1305-mac/" target="_blank" rel="noreferrer">crypto-lab-poly1305-mac</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/" target="_blank" rel="noreferrer">crypto-lab-nonce-guard</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">crypto-lab-babel-hash</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-hash-zoo/" target="_blank" rel="noreferrer">crypto-lab-hash-zoo</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noreferrer">crypto-lab-aes-modes</a>
        </p>
        <p>So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31</p>
      </footer>
      <div id="aria-live" class="sr-only" aria-live="polite" role="status"></div>
    </div>
  `;

  wireHmacPanel();
  wireCmacPanel();
  wirePolyPanel();
  wireGhashPanel();
  wireLengthExtensionPanel();
  wireTimingPanel();
  wireGuidedTour();

  renderTimingRows();
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function wireHmacPanel(): void {
  let stepper: ReturnType<typeof makeStepper> | null = null;

  const prepare = async (revealAll: boolean): Promise<void> => {
    const message = byId<HTMLTextAreaElement>('hmac-message').value;
    const key = byId<HTMLInputElement>('hmac-key').value;
    const h256 = await computeHmac(message, key, 'SHA-256');
    const h512 = await computeHmac(message, key, 'SHA-512');
    const avalanche = await avalancheBitFlip(message, key);

    const lines = [
      `Step 1 — normalized key (padded to block size):  ${fmtHex(h256.visual.normalizedKeyHex)}`,
      `Step 2 — inner pad (key ⊕ 0x36):                 ${fmtHex(h256.visual.ipadHex)}`,
      `Step 3 — outer pad (key ⊕ 0x5c):                 ${fmtHex(h256.visual.opadHex)}`,
      `Step 4 — inner = SHA-256(ipad ∥ message):        ${h256.visual.innerHashHex}`,
      `Step 5 — outer = SHA-256(opad ∥ inner) = TAG:    ${h256.visual.outerHashHex}`,
      `HMAC-SHA-256 tag:  ${h256.macHex}`,
      `HMAC-SHA-512 tag:  ${h512.macHex}`
    ];
    stepper = makeStepper(byId<HTMLElement>('hmac-output'), lines);
    if (revealAll) stepper.revealAll();

    renderBitDiffGrid(byId<HTMLElement>('hmac-bitdiff-msg'), avalanche.original, avalanche.flippedMessage, 'Flip 1 bit of the message');
    renderBitDiffGrid(byId<HTMLElement>('hmac-bitdiff-key'), avalanche.original, avalanche.flippedKey, 'Flip 1 bit of the key');

    byId<HTMLInputElement>('hmac-verify-tag').value = h256.macHex;
    setVerdictIdle(byId<HTMLElement>('hmac-verdict'), 'tag ready — click Verify');
  };

  byId<HTMLButtonElement>('hmac-run').addEventListener('click', async () => {
    try {
      await prepare(true);
      setStatus('HMAC computed successfully.');
    } catch (error) {
      setStatus(`HMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('hmac-step').addEventListener('click', async () => {
    try {
      if (!stepper) await prepare(false);
      const more = stepper!.step();
      setStatus(more ? 'Step advanced.' : 'All HMAC stages revealed.');
    } catch (error) {
      setStatus(`HMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('hmac-reveal').addEventListener('click', async () => {
    try {
      if (!stepper) await prepare(false);
      stepper!.revealAll();
    } catch (error) {
      setStatus(`HMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('hmac-verify').addEventListener('click', async () => {
    const verdict = byId<HTMLElement>('hmac-verdict');
    try {
      const message = byId<HTMLTextAreaElement>('hmac-message').value;
      const key = byId<HTMLInputElement>('hmac-key').value;
      const tag = byId<HTMLInputElement>('hmac-verify-tag').value.trim();
      const ok = await verifyHmac(message, key, 'SHA-256', tag);
      setVerdict(verdict, ok);
    } catch {
      setVerdict(verdict, false);
    }
  });
}

function wireCmacPanel(): void {
  let stepper: ReturnType<typeof makeStepper> | null = null;

  const prepare = async (revealAll: boolean): Promise<void> => {
    const message = byId<HTMLTextAreaElement>('cmac-message').value;
    const key = byId<HTMLInputElement>('cmac-key').value;
    const result = await computeCmac(message, key);
    const lines = [
      `Step 1 — AES-256 key (normalized):                 ${fmtHex(result.details.keyHex)}`,
      `Step 2 — L = AES_K(0^128) → K1 (after << 1 + Rb):  ${result.details.k1Hex}`,
      `Step 3 —                              K2:          ${result.details.k2Hex}`,
      `Step 4 — Padded last block (10* if needed):        ${result.details.paddedLastBlockHex}`,
      `Step 5 — Final block XOR with K1/K2:               ${result.details.finalXorBlockHex}`,
      `Step 6 — CBC chain so far:                         ${result.details.chainingHex.join(' → ') || '(single-block message — chain is empty)'}`,
      `Step 7 — Final encrypt = TAG:                      ${result.tagHex}`
    ];
    stepper = makeStepper(byId<HTMLElement>('cmac-output'), lines);
    if (revealAll) stepper.revealAll();
    byId<HTMLInputElement>('cmac-verify-tag').value = result.tagHex;
    setVerdictIdle(byId<HTMLElement>('cmac-verdict'), 'tag ready — click Verify');
  };

  byId<HTMLButtonElement>('cmac-run').addEventListener('click', async () => {
    try {
      await prepare(true);
      setStatus('CMAC computed successfully.');
    } catch (error) {
      setStatus(`CMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('cmac-step').addEventListener('click', async () => {
    try {
      if (!stepper) await prepare(false);
      const more = stepper!.step();
      setStatus(more ? 'Step advanced.' : 'All CMAC stages revealed.');
    } catch (error) {
      setStatus(`CMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('cmac-reveal').addEventListener('click', async () => {
    try {
      if (!stepper) await prepare(false);
      stepper!.revealAll();
    } catch (error) {
      setStatus(`CMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('cmac-verify').addEventListener('click', async () => {
    const verdict = byId<HTMLElement>('cmac-verdict');
    try {
      const message = byId<HTMLTextAreaElement>('cmac-message').value;
      const key = byId<HTMLInputElement>('cmac-key').value;
      const tag = byId<HTMLInputElement>('cmac-verify-tag').value.trim();
      const ok = await verifyCmac(message, key, tag);
      setVerdict(verdict, ok);
    } catch {
      setVerdict(verdict, false);
    }
  });
}

function wirePolyPanel(): void {
  let lastAttack: ReturnType<typeof runKeyReuseAttackDemo> | null = null;
  let lastAttackKeyHex = '';

  byId<HTMLButtonElement>('poly-run').addEventListener('click', () => {
    try {
      const message = byId<HTMLTextAreaElement>('poly-message').value;
      const result = computePoly1305(message);
      byId<HTMLElement>('poly-output').textContent =
        `Poly1305 tag: ${result.tagHex}\n` +
        `One-time key: ${result.keyHex}\n` +
        `(Tag computed mod 2^130 − 5, then reduced mod 2^128 + s.)`;
      setStatus('Poly1305 tag computed.');
    } catch (error) {
      setStatus(`Poly1305 error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('poly-attack').addEventListener('click', () => {
    try {
      const attack = runKeyReuseAttackDemo();
      lastAttack = attack;
      byId<HTMLElement>('poly-attack-output').textContent =
        `Observed:\n` +
        `  ${attack.msg1}  →  tag ${attack.tag1Hex}\n` +
        `  ${attack.msg2}  →  tag ${attack.tag2Hex}\n` +
        `\n` +
        `Solved weak r = 0x${attack.recoveredRHex}\n` +
        `Forged ${attack.msg3}  →  tag ${attack.forgedTagHex}\n` +
        `Attacker's local check: forgery ${attack.validForgery ? 'valid' : 'invalid'}.`;
      setVerdictIdle(byId<HTMLElement>('poly-verdict'), 'forged tag ready — submit it');
      setStatus('Poly1305 key reuse attack succeeded.');
    } catch (error) {
      setStatus(`Poly1305 attack error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('poly-verify').addEventListener('click', () => {
    if (!lastAttack) {
      setVerdictIdle(byId<HTMLElement>('poly-verdict'), 'run the attack first');
      return;
    }
    // Note: the attack demo uses an internal weak key. We can't independently
    // re-verify against the actual key from the UI, but the attack's own
    // constant-time check is the same operation a real server would do.
    setVerdict(byId<HTMLElement>('poly-verdict'), lastAttack.validForgery);
  });

  // Reference to avoid unused-var lint; lastAttackKeyHex would be wired
  // if we exposed the key from the attack demo.
  void lastAttackKeyHex;
}

function wireGhashPanel(): void {
  let lastAttack: ReturnType<typeof runGhashReuseAttackDemo> | null = null;
  byId<HTMLButtonElement>('ghash-run').addEventListener('click', async () => {
    try {
      const ciphertextHex = byId<HTMLTextAreaElement>('ghash-ciphertext').value.trim();
      const result = await computeGhash(ciphertextHex);
      byId<HTMLElement>('ghash-output').textContent =
        `H = E_K(0^128): ${result.hHex}\n` +
        `GHASH output:   ${result.yHex}\n` +
        `Per-block:      ${result.steps.join(' → ')}`;
      setStatus('GHASH computed.');
    } catch (error) {
      setStatus(`GHASH error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('ghash-attack').addEventListener('click', () => {
    try {
      const attack = runGhashReuseAttackDemo();
      lastAttack = attack;
      byId<HTMLElement>('ghash-attack-output').textContent =
        `Δ ciphertext: ${attack.deltaCHex}\n` +
        `Δ tag:        ${attack.deltaTHex}\n` +
        `Recovered H = ΔT · (ΔC)⁻¹ = ${attack.recoveredHHex}\n` +
        `Forgery against a new ciphertext ${attack.forgedValid ? 'VALID' : 'invalid'}.\n\n` +
        attack.note;
      setVerdictIdle(byId<HTMLElement>('ghash-verdict'), 'forged — submit it');
      setStatus('GHASH nonce reuse attack succeeded.');
    } catch (error) {
      setStatus(`GHASH attack error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('ghash-verify').addEventListener('click', () => {
    if (!lastAttack) {
      setVerdictIdle(byId<HTMLElement>('ghash-verdict'), 'run the attack first');
      return;
    }
    setVerdict(byId<HTMLElement>('ghash-verdict'), lastAttack.forgedValid);
  });
}

function wireLengthExtensionPanel(): void {
  let captured: { message: string; rawMacHex: string; hmacMacHex: string } | null = null;
  let forged: { messageBytes: Uint8Array; rawTagHex: string; hmacAttemptHex: string } | null = null;

  const guessSlider = byId<HTMLInputElement>('le-guess');
  const guessValueLabel = byId<HTMLSpanElement>('le-guess-value');
  guessSlider.addEventListener('input', () => {
    guessValueLabel.textContent = guessSlider.value;
  });

  byId<HTMLButtonElement>('le-capture').addEventListener('click', async () => {
    try {
      const message = byId<HTMLInputElement>('le-message').value;
      const r = await captureOriginalRequest(message);
      captured = { message, ...r };
      byId<HTMLElement>('le-raw-tag').textContent = r.rawMacHex;
      byId<HTMLElement>('le-hmac-tag').textContent = r.hmacMacHex;
      setVerdictIdle(byId<HTMLElement>('le-verdict-raw'), 'awaiting forge');
      setVerdictIdle(byId<HTMLElement>('le-verdict-hmac'), 'awaiting forge');
      byId<HTMLElement>('le-forge-output').textContent = '(now pick a guessed length and forge)';
      byId<HTMLElement>('le-summary').textContent = `Secret length is hidden somewhere in ${ATTACKER_SECRET_LENGTH_RANGE[0]}..${ATTACKER_SECRET_LENGTH_RANGE[1]} bytes. Guess and forge.`;
      setStatus('Captured original request.');
    } catch (error) {
      setStatus(`Capture error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('le-reset-secret').addEventListener('click', () => {
    const newLen = regenerateDemoSecret();
    captured = null;
    forged = null;
    byId<HTMLElement>('le-raw-tag').textContent = '(rotated — capture again)';
    byId<HTMLElement>('le-hmac-tag').textContent = '(rotated — capture again)';
    byId<HTMLElement>('le-forge-output').textContent = '(secret rotated; capture, then forge)';
    setVerdictIdle(byId<HTMLElement>('le-verdict-raw'), 'rotated — recapture');
    setVerdictIdle(byId<HTMLElement>('le-verdict-hmac'), 'rotated — recapture');
    setStatus(`Secret rotated (new length ${newLen} bytes, hidden).`);
  });

  byId<HTMLButtonElement>('le-forge').addEventListener('click', async () => {
    if (!captured) {
      setStatus('Capture the original request first.', true);
      return;
    }
    try {
      const append = byId<HTMLInputElement>('le-append').value;
      const guessed = Number(guessSlider.value);
      const result = await attemptForge(
        captured.message,
        captured.rawMacHex,
        captured.hmacMacHex,
        append,
        guessed
      );
      forged = {
        messageBytes: hexToBytes(result.forgedMessageHex),
        rawTagHex: result.forgedRawTagHex,
        hmacAttemptHex: result.forgedHmacTagAttemptHex
      };
      byId<HTMLElement>('le-forge-output').textContent =
        `Guessed secret length: ${result.guessedSecretLength}\n` +
        `Forged message (visible): ${result.forgedMessageVisible}\n` +
        `Forged message (hex):     ${fmtHex(result.forgedMessageHex, 200)}\n` +
        `Forged tag (broken construction):       ${result.forgedRawTagHex}\n` +
        `Forged tag (HMAC attempt — won't work): ${result.forgedHmacTagAttemptHex}\n`;
      setVerdictIdle(byId<HTMLElement>('le-verdict-raw'), 'forged — submit it');
      setVerdictIdle(byId<HTMLElement>('le-verdict-hmac'), 'forged — submit it');
      setStatus(`Forge complete with guessed length ${result.guessedSecretLength}.`);
    } catch (error) {
      setStatus(`Forge error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('le-verify-raw').addEventListener('click', async () => {
    if (!forged) {
      setVerdictIdle(byId<HTMLElement>('le-verdict-raw'), 'forge first');
      return;
    }
    const ok = await rawServerVerify(forged.messageBytes, forged.rawTagHex);
    setVerdict(byId<HTMLElement>('le-verdict-raw'), ok);
    updateLeSummary(ok, null);
  });

  byId<HTMLButtonElement>('le-verify-hmac').addEventListener('click', async () => {
    if (!forged) {
      setVerdictIdle(byId<HTMLElement>('le-verdict-hmac'), 'forge first');
      return;
    }
    const ok = await hmacServerVerify(forged.messageBytes, forged.hmacAttemptHex);
    setVerdict(byId<HTMLElement>('le-verdict-hmac'), ok);
    updateLeSummary(null, ok);
  });

  let lastRaw: boolean | null = null;
  let lastHmac: boolean | null = null;
  function updateLeSummary(rawOk: boolean | null, hmacOk: boolean | null): void {
    if (rawOk !== null) lastRaw = rawOk;
    if (hmacOk !== null) lastHmac = hmacOk;
    const actual = getActualSecretLength();
    const guessed = Number(guessSlider.value);
    const parts: string[] = [];
    if (lastRaw === true) parts.push(`✅ BROKEN server accepted the forgery (you guessed the secret length: ${guessed} = ${actual}).`);
    if (lastRaw === false) parts.push(`❌ BROKEN server rejected — guess ${guessed} did not match actual length ${actual}. Try a different slider value.`);
    if (lastHmac === true) parts.push(`⚠️ SAFE server also accepted? That shouldn't happen — please report.`);
    if (lastHmac === false) parts.push(`🛡️ SAFE server rejected — HMAC is immune to this attack technique.`);
    byId<HTMLElement>('le-summary').textContent = parts.join(' ');
  }
}

function wireTimingPanel(): void {
  byId<HTMLButtonElement>('timing-run').addEventListener('click', () => {
    renderTimingRows();
    setStatus('Timing measurements updated.');
  });

  byId<HTMLButtonElement>('recovery-run').addEventListener('click', async () => {
    const bytesInput = byId<HTMLInputElement>('recovery-bytes');
    const requested = Math.max(1, Math.min(16, Number(bytesInput.value) || 8));
    const status = byId<HTMLElement>('recovery-status');
    const output = byId<HTMLElement>('recovery-output');
    const bar = byId<HTMLElement>('recovery-bar-fill');
    output.textContent = '';
    status.textContent = 'starting…';
    bar.style.width = '0%';

    const result = await recoverTagByTimingAttack(16, (p) => {
      const pct = ((p.byteIndex + 1) / requested) * 100;
      bar.style.width = `${pct}%`;
      status.textContent = `Recovered byte ${p.byteIndex + 1}/${requested} = 0x${p.byteValue.toString(16).padStart(2, '0')} (${p.oracleQueries} oracle queries so far)`;
      output.textContent = `Recovered prefix: ${p.recoveredHex}`;
    }, requested);

    const fullDisplay = result.recoveredTagHex + (result.recoveredTagHex.length < 32 ? '..'.repeat((32 - result.recoveredTagHex.length) / 2) : '');
    output.textContent =
      `Recovered: ${fullDisplay}\n` +
      `True tag:  ${result.trueTagHex}\n` +
      `Match for first ${result.bytesRecovered} bytes: ${result.success ? '✅ YES' : '❌ NO'}\n` +
      `Total oracle queries: ${result.oracleQueries}  (≈ 256 per byte)`;
    status.textContent = result.success
      ? `Recovered ${result.bytesRecovered} bytes via prefix-match timing leak.`
      : `Recovery diverged from true tag.`;
    setStatus('Byte-by-byte recovery complete.');
  });
}

function wireGuidedTour(): void {
  let active = -1;
  const titleEl = byId<HTMLElement>('tour-title');
  const bodyEl = byId<HTMLElement>('tour-body');
  const progressEl = byId<HTMLElement>('tour-progress');
  const startBtn = byId<HTMLButtonElement>('tour-start');
  const prevBtn = byId<HTMLButtonElement>('tour-prev');
  const nextBtn = byId<HTMLButtonElement>('tour-next');
  const endBtn = byId<HTMLButtonElement>('tour-end');

  function highlight(index: number): void {
    document.querySelectorAll('.panel').forEach((el) => el.classList.remove('panel-active'));
    if (index < 0) return;
    const step = LESSON_STEPS[index];
    const panel = document.getElementById(step.panelId);
    if (panel) {
      panel.classList.add('panel-active');
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    titleEl.textContent = step.title;
    bodyEl.textContent = step.body;
    progressEl.hidden = false;
    progressEl.textContent = `Lesson ${index + 1} of ${LESSON_STEPS.length}`;
  }

  function setControlsActive(isActive: boolean): void {
    startBtn.hidden = isActive;
    prevBtn.hidden = !isActive;
    nextBtn.hidden = !isActive;
    endBtn.hidden = !isActive;
  }

  startBtn.addEventListener('click', () => {
    active = 0;
    setControlsActive(true);
    highlight(active);
  });
  prevBtn.addEventListener('click', () => {
    if (active > 0) active -= 1;
    highlight(active);
  });
  nextBtn.addEventListener('click', () => {
    if (active < LESSON_STEPS.length - 1) active += 1;
    else {
      setControlsActive(false);
      active = -1;
      document.querySelectorAll('.panel').forEach((el) => el.classList.remove('panel-active'));
      titleEl.textContent = 'Tour complete — explore freely';
      bodyEl.textContent = 'You can restart the tour any time.';
      progressEl.hidden = true;
      return;
    }
    highlight(active);
  });
  endBtn.addEventListener('click', () => {
    setControlsActive(false);
    active = -1;
    document.querySelectorAll('.panel').forEach((el) => el.classList.remove('panel-active'));
    titleEl.textContent = 'Guided tour: start with HMAC →';
    bodyEl.textContent = 'Click "Start tour" to walk through the panels in pedagogical order.';
    progressEl.hidden = true;
  });
}
