import { avalancheBitFlip, computeHmac, verifyHmac } from './hmac';
import { computeCmac, verifyCmac } from './cmac';
import { computePoly1305, runKeyReuseAttackDemo } from './poly1305';
import { computeGhash, runGhashReuseAttackDemo } from './ghash';
import {
  ATTACKER_SECRET_LENGTH_RANGE,
  attemptForge,
  captureOriginalRequest,
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

// Render a single 128-bit row as 128 tiny cells (set bits filled).
function bitRow(hex: string, cssClass: string): HTMLElement {
  const bytes = hexToBytes(hex);
  const row = document.createElement('div');
  row.className = `bitrow ${cssClass}`;
  for (let i = 0; i < 16; i += 1) {
    const byte = bytes[i] ?? 0;
    for (let bit = 7; bit >= 0; bit -= 1) {
      const cell = document.createElement('span');
      cell.className = 'bitrow-cell';
      if (((byte >> bit) & 1) === 1) cell.classList.add('bitrow-on');
      row.appendChild(cell);
    }
  }
  return row;
}

// Visualize T1 XOR T2 = (C1 XOR C2)·H as three stacked 128-bit bit-rows on each
// side of the equation, so the learner literally sees the shared H term cancel
// out under XOR and the two sides land on identical bit patterns.
function renderGhashLinearity(
  container: HTMLElement,
  t1Hex: string,
  t2Hex: string,
  deltaTHex: string,
  c1Hex: string,
  c2Hex: string,
  deltaCHex: string
): void {
  container.textContent = '';

  const makeBlock = (
    labelHtml: string,
    aLabel: string,
    aHex: string,
    bLabel: string,
    bHex: string,
    resultLabel: string,
    resultHex: string
  ): HTMLElement => {
    const block = document.createElement('div');
    block.className = 'linviz-block';
    const cap = document.createElement('p');
    cap.className = 'linviz-cap';
    cap.innerHTML = labelHtml;
    block.appendChild(cap);
    const grid = document.createElement('div');
    grid.className = 'linviz-grid';
    const addLine = (name: string, hex: string, cls: string, op?: string): void => {
      const opCell = document.createElement('span');
      opCell.className = 'linviz-op';
      opCell.textContent = op ?? '';
      opCell.setAttribute('aria-hidden', 'true');
      const nameCell = document.createElement('span');
      nameCell.className = 'linviz-name';
      nameCell.textContent = name;
      grid.append(opCell, nameCell, bitRow(hex, cls));
    };
    addLine(aLabel, aHex, 'bitrow-t');
    addLine(bLabel, bHex, 'bitrow-t', '⊕');
    addLine(resultLabel, resultHex, 'bitrow-delta', '=');
    block.appendChild(grid);
    return block;
  };

  const left = makeBlock(
    'Left side: <code>T1 ⊕ T2</code>',
    'T1', t1Hex, 'T2', t2Hex, 'T1⊕T2', deltaTHex
  );
  const right = makeBlock(
    'Right side: <code>(C1 ⊕ C2)</code>, then ×H',
    'C1', c1Hex, 'C2', c2Hex, 'C1⊕C2', deltaCHex
  );

  const eq = document.createElement('p');
  eq.className = 'linviz-equals';
  eq.innerHTML = 'The shared <code>·H</code> factor is identical in T1 and T2, so it survives on both sides. XORing gives <code>T1⊕T2 = (C1⊕C2)·H</code> — one equation, one unknown H. Invert <code>(C1⊕C2)</code> in the field and <strong>H falls out</strong>.';

  container.append(left, right, eq);
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

const POLY_SRC = `// Two messages under the SAME one-time key leak r.
// tag = ((m * r) mod (2^130-5) + s) mod 2^128
// TEACHING SIMPLIFICATION: r is constrained to 16 bits so that m*r
// stays below 2^130-5 (the mod-P reduction never fires). That makes the
// recovery a live 16-bit search in the browser. With a full ~106-bit r the
// per-message mod-P quotient (~115 bits) is unknown to the attacker, so two
// tags are NOT enough — do not read "16-bit" as a property of real Poly1305.
for (let rGuess = 0n; rGuess <= 0xffffn; rGuess++) {
  const sGuess = (tag1 - (m1*rGuess % P) + MOD) % MOD;
  if (((m2*rGuess % P) + sGuess) % MOD === tag2) {
    // forge any new message m3 with the recovered (r, s) — genuinely valid.
  }
}`;

const GHASH_SRC = `// Live Forbidden Attack — nothing is hard-coded.
// A fresh AES key is generated each run; H = E_K(0^128) via WebCrypto.
// Two random single-block ciphertexts are tagged under the reused nonce:
//   T1 = C1 * H,  T2 = C2 * H   (GHASH is linear in GF(2^128))
//   T1 ^ T2 = (C1 ^ C2) * H
//   H = (T1 ^ T2) * (C1 ^ C2)^(-1)
const H_true = await aesEncryptBlock(key, ZERO16);   // hidden from attacker
const deltaT = xor16(gf128Mul(C1, H_true), gf128Mul(C2, H_true));
const deltaC = xor16(C1, C2);
const H = gf128Mul(deltaT, gfInverse(deltaC));        // == H_true
// Forge any target; the server (holding H_true) confirms the tag.`;

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
  { panelId: 'p3', title: '4. Poly1305 — fast, one-time only', body: 'A polynomial MAC. Reusing the one-time key destroys authenticity: the two tags become linear equations in r. The demo uses a deliberately narrowed r so the recovery runs live in your browser — the algebra is real, the search space is a teaching simplification (disclosed in the panel).' },
  { panelId: 'p4', title: '5. GHASH — linear in GF(2^128)', body: "GHASH is what authenticates AES-GCM. It is linear in the field, so nonce reuse leaks the hash subkey H. This is the Forbidden Attack." },
  { panelId: 'p6', title: '6. Timing attack — non-constant-time compare', body: 'A naive byte-by-byte equality leaks prefix-match length. Watch a real byte-by-byte tag recovery driven entirely by that signal.' }
];

export function renderApp(container: HTMLElement): void {
  container.innerHTML = `
    <div class="page">
      <a class="skip-link" href="#main-content" aria-label="Skip to main content">Skip to main content</a>
      <button
        id="theme-toggle"
        class="theme-toggle"
        aria-label="Switch to light mode"
      >🌙</button>
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">MAC Race</h1>
          <p class="cl-hero-sub">HMAC · AES-CMAC · Poly1305 · GHASH</p>
          <p class="cl-hero-desc">Build HMAC, AES-CMAC, Poly1305, and GHASH tags side by side, then trigger the misuse modes — length extension, one-time-key reuse, nonce reuse, and non-constant-time comparison — that separate a safe MAC from a broken one.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">A MAC is the line between an authenticated message and a forged one. The classic disasters — Flickr's length-extension forgery, AEAD nonce reuse leaking the auth key, tag comparison leaking timing — came not from weak math but from misusing the primitive.</p>
        </aside>
      </header>

      <section class="intro-card" aria-labelledby="intro-title">
        <div class="intro-text">
          <h2 id="intro-title">What is a MAC?</h2>
          <p class="intro-lede">A <strong>Message Authentication Code (MAC)</strong> is a short tag computed from a message <em>and</em> a secret key. Send the message with its tag; the receiver — who shares the key — recomputes the tag and accepts only if it matches. Change one byte of the message and the tag no longer matches, so the forgery is <strong>rejected</strong>.</p>
          <p class="intro-why">
            <span class="intro-q">Why can't I just hash the message?</span>
            A plain hash <code>H(message)</code> has no secret, so anyone can recompute it — it proves the message was not <em>corrupted</em>, not that it came from someone holding the key. A MAC mixes in a key the attacker does not have. (Naively stitching the key in as <code>H(secret ∥ message)</code> is <em>also</em> broken — that is the length-extension trap in Lesson 2.)
          </p>
        </div>
        <figure class="mac-anim" aria-label="Animation: a message and secret key flow into a MAC function that emits a fixed-size tag; the receiver accepts a matching tag but rejects a tampered message">
          <div class="mac-stage">
            <div class="mac-inputs">
              <span class="mac-token mac-msg">message</span>
              <span class="mac-plus" aria-hidden="true">+</span>
              <span class="mac-token mac-key">secret key</span>
            </div>
            <span class="mac-arrow" aria-hidden="true">→</span>
            <div class="mac-box" aria-hidden="true">MAC</div>
            <span class="mac-arrow" aria-hidden="true">→</span>
            <span class="mac-token mac-tag">tag</span>
          </div>
          <div class="mac-stage mac-recv">
            <div class="mac-recv-row mac-recv-ok">
              <span class="mac-token mac-msg">message</span>
              <span class="mac-token mac-tag">tag</span>
              <span class="mac-arrow" aria-hidden="true">→</span>
              <span class="mac-token mac-recv-box">recompute&nbsp;&amp;&nbsp;compare</span>
              <span class="mac-arrow" aria-hidden="true">→</span>
              <span class="mac-verdict-chip mac-accept">✓ ACCEPTED</span>
            </div>
            <div class="mac-recv-row mac-recv-bad">
              <span class="mac-token mac-msg mac-tampered">message<span class="mac-tamper-mark">✎</span></span>
              <span class="mac-token mac-tag">tag</span>
              <span class="mac-arrow" aria-hidden="true">→</span>
              <span class="mac-token mac-recv-box">recompute&nbsp;&amp;&nbsp;compare</span>
              <span class="mac-arrow" aria-hidden="true">→</span>
              <span class="mac-verdict-chip mac-reject">✗ REJECTED</span>
            </div>
          </div>
          <figcaption class="mac-caption">Attacker (no key) alters the message but cannot recompute a matching tag, so the receiver rejects it.</figcaption>
        </figure>
      </section>

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
            <span class="chip chip-ok">RECOMMENDED DEFAULT</span>
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
            <p class="note note-why"><strong>Why ~50% matters for a MAC:</strong> if flipping one message bit only changed a few tag bits, an attacker could nudge a message toward a target tag and steer forgeries. A ~50% flip means the tag is <em>unpredictable</em> — no local edit gives the attacker any handle on the output, which is exactly the security property a MAC needs.</p>
            <div id="hmac-bitdiff-msg" class="bitdiff-block"></div>
            <div id="hmac-bitdiff-key" class="bitdiff-block"></div>
          </div>

          <div class="verifier" role="group" aria-label="HMAC server verifier">
            <h3>Server verifies</h3>
            <label for="hmac-verify-tag">Candidate tag (hex)</label>
            <input id="hmac-verify-tag" aria-label="HMAC candidate tag" />
            <div class="button-row">
              <button id="hmac-verify" aria-label="Verify HMAC tag">Verify on server</button>
              <span id="hmac-verdict" class="verdict verdict-idle">awaiting input</span>
            </div>
          </div>

          <p class="note">${gloss('FIPS 198-1', 'US federal standard (NIST) that specifies HMAC.')}: HMAC uses nested hashing with ${gloss('ipad/opad', 'two fixed one-byte patterns (0x36 and 0x5c) repeated to a block, XORed with the key for the inner and outer hash so the two hash passes use different keyed inputs.')}, so length extension against bare SHA-256 does not apply.</p>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src" tabindex="0">${escapeHtml(HMAC_SRC)}</pre></details>
        </section>

        <section class="panel" id="p2" aria-labelledby="p2-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 3</span>
            <h2 id="p2-title">CMAC</h2>
            <span class="chip chip-ok">RECOMMENDED (FIPS contexts)</span>
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

          <div class="verifier" role="group" aria-label="CMAC server verifier">
            <h3>Server verifies</h3>
            <label for="cmac-verify-tag">Candidate tag (hex)</label>
            <input id="cmac-verify-tag" aria-label="CMAC candidate tag" />
            <div class="button-row">
              <button id="cmac-verify" aria-label="Verify CMAC tag">Verify on server</button>
              <span id="cmac-verdict" class="verdict verdict-idle">awaiting input</span>
            </div>
          </div>

          <p class="note">NIST SP 800-38B: derives K1/K2 from AES_K(0^128), applies 10* padding, and XORs final block before last encryption.</p>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src" tabindex="0">${escapeHtml(CMAC_SRC)}</pre></details>
        </section>

        <section class="panel" id="p3" aria-labelledby="p3-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 4</span>
            <h2 id="p3-title">Poly1305</h2>
            <span class="chip chip-ok">RECOMMENDED (always with ChaCha20)</span>
          </div>

          <label for="poly-message">Message</label>
          <textarea id="poly-message" aria-label="Poly1305 message input">Cryptographic Forum Research Group</textarea>
          <div class="button-row">
            <button id="poly-run" aria-label="Compute Poly1305 tag">Compute tag</button>
          </div>
          <pre id="poly-output" class="hex" role="status" aria-live="polite" aria-label="Poly1305 output"></pre>

          <div class="attack-pane" role="group" aria-label="Poly1305 one-time key reuse attack">
            <h3>You are the attacker</h3>
            <p class="note">A buggy server reused the <em>same</em> one-time key for two invoice messages. The two tags are linear equations in the ${gloss('clamped r', "half of the Poly1305 one-time key, with 22 specific bits forced to 0 ('clamped') so the field arithmetic stays fast and side-channel-safe; the other half is the additive value s.")} value <code>r</code>: <code>tag = (m·r mod 2¹³⁰⁻⁵ + s) mod 2¹²⁸</code>. Recover <code>r</code> and forge a new invoice.</p>
            <p class="note"><strong>Honest disclosure:</strong> real Poly1305 <code>r</code> is a ~106-bit clamped value, and each single-block accumulator is reduced mod 2¹³⁰⁻⁵ by a ~115-bit quotient the attacker never sees — so recovering <code>r</code> from just two tags is <em>not</em> tractable. To make the algebra runnable live in your browser this demo constrains <code>r</code> to 16 bits (so <code>m·r &lt; 2¹³⁰⁻⁵</code> and the reduction vanishes). The forgery it produces is genuinely valid against the real key; the <em>simplification is only the size of the search</em>. Generic Poly1305 reuse is catastrophic but not literally 16-bit-breakable.</p>
            <div class="button-row">
              <button id="poly-attack" aria-label="Run Poly1305 key reuse attack">Run reuse attack →</button>
            </div>
            <pre id="poly-attack-output" class="hex" role="status" aria-live="polite" aria-label="Poly1305 attack output"></pre>
          </div>

          <div class="verifier" role="group" aria-label="Poly1305 server verifier">
            <h3>Server verifies</h3>
            <p class="note">Submit the forged tag from the attack against the original key. Both messages were authenticated with that key — so the server <em>will</em> accept your forgery.</p>
            <div class="button-row">
              <button id="poly-verify" aria-label="Submit forged tag to Poly1305 server">Submit forged tag</button>
              <span id="poly-verdict" class="verdict verdict-idle">awaiting attack</span>
            </div>
          </div>

          <div class="callout-cve" role="group" aria-label="Incident callout">
            <strong>📜 RFC 8439 warns explicitly:</strong> "The key MUST be unpredictable for each invocation." Implementations that reused Poly1305 keys (early Wireguard / experimental QUIC ports, 2015–2018 era code) had to be patched specifically for this property.
          </div>

          <p class="note">RFC 8439: Poly1305 must use a unique one-time key per message, usually derived by ChaCha20 with a unique nonce.</p>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src" tabindex="0">${escapeHtml(POLY_SRC)}</pre></details>
        </section>

        <section class="panel" id="p4" aria-labelledby="p4-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 5</span>
            <h2 id="p4-title">GHASH</h2>
            <span class="chip chip-warn">SECURE only with nonce discipline</span>
          </div>
          <label for="ghash-ciphertext">Ciphertext (hex)</label>
          <textarea id="ghash-ciphertext" aria-label="GHASH ciphertext hex input">0388dace60b6a392f328c2b971b2fe78</textarea>
          <div class="button-row">
            <button id="ghash-run" aria-label="Compute GHASH">Compute GHASH</button>
          </div>
          <pre id="ghash-output" class="hex" role="status" aria-live="polite" aria-label="GHASH output"></pre>

          <div class="attack-pane" role="group" aria-label="GHASH nonce reuse attack">
            <h3>You are the attacker</h3>
            <p class="note">Two ciphertexts encrypted under the <em>same</em> AES-GCM nonce share the same hash subkey H. With a single delta you can solve for H and forge tags for any other ciphertext.</p>

            <div class="linviz" role="group" aria-label="Why nonce reuse leaks H: the linear algebra collapses">
              <p class="linviz-lede"><strong>Why does reuse leak H?</strong> Because a single-block tag is just <code>T = C · H</code> and the field is ${gloss('linear', 'f is linear when f(A) XOR f(B) = f(A XOR B). Multiplication by a fixed H in GF(2^128) is linear, so XORing two tags equals the tag of the XORed ciphertexts.')}. Watch the two tags XOR together: everywhere the H term is <em>identical</em>, XOR cancels it — until only <code>(C1 ⊕ C2)·H</code> is left, and H is the one unknown you can now solve for.</p>
              <div id="ghash-linviz-rows" class="linviz-rows" role="img" aria-label="Bit rows showing T1 XOR T2 equals (C1 XOR C2) times H, with the shared H term cancelling under XOR">
                <p class="note linviz-idle">Run the attack below to watch the algebra collapse on the real bits.</p>
              </div>
            </div>

            <div class="button-row">
              <button id="ghash-attack" aria-label="Run GHASH nonce reuse attack">Run nonce reuse attack →</button>
            </div>
            <pre id="ghash-attack-output" class="hex" role="status" aria-live="polite" tabindex="0" aria-label="GHASH attack output"></pre>
          </div>

          <div class="verifier" role="group" aria-label="GHASH server verifier">
            <h3>Server verifies</h3>
            <p class="note">After the nonce-reuse attack recovers H, the attacker can issue a forged tag for any ciphertext. The demo's local constant-time check (shown above) is the same operation a real GCM endpoint runs.</p>
            <div class="button-row">
              <button id="ghash-verify" aria-label="Submit forged GHASH tag">Submit forged tag</button>
              <span id="ghash-verdict" class="verdict verdict-idle">awaiting attack</span>
            </div>
          </div>

          <div class="callout-cve" role="group" aria-label="Incident callout">
            <strong>🔓 Forbidden Attack (Böck, Zauner, Devlin — 2016):</strong> a scan of the public web found 184 HTTPS servers and IoT devices reusing GCM nonces. Researchers extracted authentication keys and demonstrated full message forgery over real TLS.
          </div>

          <p class="note">NIST SP 800-38D: GHASH is linear in ${gloss('GF(2^128)', 'a finite field of 2^128 elements: 128-bit blocks where "add" is bitwise XOR and "multiply" is polynomial multiplication modulo a fixed irreducible polynomial. "Linear" means GHASH(A) XOR GHASH(B) = GHASH(A XOR B).')}. Reusing a GCM nonce is catastrophic.</p>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src" tabindex="0">${escapeHtml(GHASH_SRC)}</pre></details>
        </section>

        <section class="panel panel-wide" id="p5" aria-labelledby="p5-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 2</span>
            <h2 id="p5-title">Length Extension Attack</h2>
            <span class="chip chip-bad">bare SHA-256 as MAC = AVOID</span>
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

            <div id="le-layout" class="le-layout" role="group" aria-label="Forged message layout" hidden>
              <p class="le-layout-cap">What the server actually hashes — <code>SHA-256(secret ∥ forged bytes)</code>:</p>
              <div class="le-blocks">
                <span class="le-seg le-seg-secret" title="Unknown to the attacker — only its LENGTH must be guessed">
                  <span class="le-seg-name">secret</span>
                  <span class="le-seg-detail">??? (length is the only unknown)</span>
                </span>
                <span class="le-seg le-seg-msg">
                  <span class="le-seg-name">original message</span>
                  <span class="le-seg-detail" id="le-seg-msg-detail">comment=10&amp;uid=7</span>
                </span>
                <span class="le-seg le-seg-glue">
                  <span class="le-seg-name">glue padding</span>
                  <span class="le-seg-detail" id="le-seg-glue-detail">\x80\x00…len</span>
                </span>
                <span class="le-seg le-seg-append">
                  <span class="le-seg-name">appended</span>
                  <span class="le-seg-detail" id="le-seg-append-detail">&amp;admin=true</span>
                </span>
              </div>
              <p class="note le-layout-why">The attacker never learns the <span class="le-key-secret">grey secret</span> — they resume SHA-256 from the <em>published tag</em> (which IS the hash's internal state after the secret+message+glue) and hash only the <span class="le-key-append">append</span> onto it. The <span class="le-key-glue">glue</span> is SHA-256's own <code>\x80 00…</code> length padding for the original block; guessing the secret's <strong>length</strong> is the sole thing that must be brute-forced.</p>
            </div>

            <pre id="le-forge-output" class="hex" tabindex="0">(capture, then forge)</pre>
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
            <strong>🔓 Flickr API (2009):</strong> Flickr's signed request scheme used <code>md5(secret &#124;&#124; query)</code>. Researchers Duong and Rizzo (later of BEAST and CRIME) demonstrated tag forgery via length extension and could call arbitrary signed API methods. Fixed by switching to HMAC.
          </div>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src" tabindex="0">${escapeHtml(LENGTHEXT_SRC)}</pre></details>
        </section>

        <section class="panel panel-wide" id="p6" aria-labelledby="p6-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 6</span>
            <h2 id="p6-title">MAC Comparison + Timing Attack</h2>
          </div>
          <div class="table-wrap" role="region" tabindex="0" aria-label="MAC comparison table">
            <table>
              <caption class="sr-only">MAC primitive comparison: construction, key size, tag size, PQ resistance, and use case</caption>
              <thead><tr><th>Primitive</th><th>Construction</th><th>Key</th><th>Tag</th><th>PQ</th><th>Use case</th></tr></thead>
              <tbody>
                <tr><td>HMAC-SHA-256</td><td>Hash (${gloss('Merkle-Damgard', 'the block-by-block construction behind SHA-1/SHA-2: each block updates a running internal state, and the final state IS the output digest — which is what makes bare prefix-hashes extendable. HMAC wraps this so the leaked state cannot be resumed.')} wrapped)</td><td>Any secret</td><td>256b</td><td>Yes</td><td>General API auth</td></tr>
                <tr><td>HMAC-SHA-512</td><td>Hash</td><td>Any secret</td><td>512b</td><td>Yes</td><td>Long-term integrity tokens</td></tr>
                <tr><td>AES-256-CMAC</td><td>Block cipher</td><td>256b AES</td><td>128b</td><td>Yes</td><td>FIPS/NIST contexts</td></tr>
                <tr><td>Poly1305</td><td>Polynomial mod 2^130-5</td><td>256b one-time</td><td>128b</td><td>Yes</td><td>ChaCha20-Poly1305</td></tr>
                <tr><td>GHASH</td><td>Polynomial mod x^128+x^7+x^2+x+1</td><td>128b subkey H</td><td>128b</td><td>Yes</td><td>AES-GCM internals</td></tr>
              </tbody>
            </table>
          </div>

          <h3>Timing differential (naive vs constant-time compare)</h3>
          <div class="button-row">
            <button id="timing-run" aria-label="Measure timing attack differences">Measure timing</button>
          </div>
          <div class="table-wrap" role="region" tabindex="0" aria-label="Timing attack measurements">
            <table>
              <caption class="sr-only">Timing attack demonstration: naive versus constant-time MAC comparison</caption>
              <thead><tr><th>Case</th><th>Naive compare</th><th>Constant-time compare</th></tr></thead>
              <tbody id="timing-rows"></tbody>
            </table>
          </div>
          <p id="timing-summary" class="note"></p>

          <div class="attack-pane">
            <h3>Byte-by-byte tag recovery</h3>
            <p class="disclosure-banner" role="note"><strong>How this oracle measures "time":</strong> single-shot wall-clock timing in a browser is far too noisy to read one tag byte. So this demo's oracle reports the <em>prefix-match length</em> directly, as an honest stand-in for "the timing signal you would get after averaging many samples." The <em>attack logic</em> — try all 256 values per position, keep the one that matches furthest, move to the next byte — is exactly the real technique; only the noise-free signal is simulated.</p>
            <p class="note">A simulated server holds a random 16-byte tag and compares submitted candidates with <code>naiveEqual</code>. The attacker submits 256 candidates per byte position and keeps whichever the oracle reports as the longest prefix match — recovering the entire tag without ever knowing the secret.</p>
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

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src" tabindex="0">${escapeHtml(TIMING_SRC)}</pre></details>
        </section>
      </main>

      <section class="why" aria-label="Why this matters">
        <h2>Why this matters</h2>
        <p>MAC failure is one of the most common causes of production cryptographic vulnerabilities. Length extension and timing attacks have repeatedly broken real systems.</p>
        <p class="links" role="group" aria-label="Cross links">
          <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noreferrer">crypto-lab</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noreferrer">crypto-lab-aes-modes</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-shadow-vault/" target="_blank" rel="noreferrer">crypto-lab-shadow-vault</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">crypto-lab-babel-hash</a>
          <a href="https://systemslibrarian.github.io/crypto-compare/#mac" target="_blank" rel="noreferrer">crypto-compare MAC</a>
        </p>
      </section>

      <footer class="footer" aria-label="Footer">
        <a class="github-badge" href="https://github.com/systemslibrarian/crypto-lab-mac-race" target="_blank" rel="noreferrer" aria-label="GitHub repository link">GitHub</a>
        <p class="links" role="group" aria-label="Related demos">Related demos:
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

// Inline glossary term: renders `term` with a dotted underline and an
// accessible tooltip (definition) reachable by hover OR keyboard focus.
// The definition text is also exposed to assistive tech via aria-label.
function gloss(term: string, definition: string): string {
  const safeTerm = escapeHtml(term);
  const safeDef = escapeHtml(definition);
  return `<span class="gloss" tabindex="0" role="note" aria-label="${safeTerm}: ${safeDef}"><span class="gloss-term">${safeTerm}</span><span class="gloss-pop" aria-hidden="true">${safeDef}</span></span>`;
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
        `Teaching setup: r constrained to ${attack.rSpaceBits} bits so the algebra runs live in-browser.\n` +
        `(Real r is ~106 bits; see note below — full 2-tag recovery is NOT tractable.)\n\n` +
        `Observed (same one-time key reused):\n` +
        `  ${attack.msg1}  →  tag ${attack.tag1Hex}\n` +
        `  ${attack.msg2}  →  tag ${attack.tag2Hex}\n` +
        `\n` +
        `Solved r = 0x${attack.recoveredRHex} (searched 2^${attack.rSpaceBits} candidates)\n` +
        `Forged ${attack.msg3}  →  tag ${attack.forgedTagHex}\n` +
        `Forgery matches the true tag under the real key: ${attack.validForgery ? 'VALID' : 'invalid'}.`;
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
    // validForgery is a constant-time comparison of the forged tag against the
    // tag the REAL key produces for m3 (poly1305(msg3, key)) — i.e. exactly the
    // check a genuine server runs. The recovered r/s reproduce the true tag.
    setVerdict(byId<HTMLElement>('poly-verdict'), lastAttack.validForgery);
  });
}

function wireGhashPanel(): void {
  let lastAttack: Awaited<ReturnType<typeof runGhashReuseAttackDemo>> | null = null;
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

  byId<HTMLButtonElement>('ghash-attack').addEventListener('click', async () => {
    try {
      const attack = await runGhashReuseAttackDemo();
      lastAttack = attack;
      renderGhashLinearity(
        byId<HTMLElement>('ghash-linviz-rows'),
        attack.t1Hex,
        attack.t2Hex,
        attack.deltaTHex,
        attack.c1Hex,
        attack.c2Hex,
        attack.deltaCHex
      );
      byId<HTMLElement>('ghash-attack-output').textContent =
        `Live H = E_K(0^128) from a fresh random AES key (hidden from attacker).\n` +
        `Observed under reused nonce:\n` +
        `  C1 ${attack.c1Hex}  →  T1 ${attack.t1Hex}\n` +
        `  C2 ${attack.c2Hex}  →  T2 ${attack.t2Hex}\n\n` +
        `Δ ciphertext: ${attack.deltaCHex}\n` +
        `Δ tag:        ${attack.deltaTHex}\n` +
        `Recovered H = ΔT · (ΔC)⁻¹ = ${attack.recoveredHHex}\n` +
        `Recovered H equals the true hidden H: ${attack.hMatchesTrue ? 'YES' : 'no'}\n\n` +
        `Forge target C3 ${attack.targetCiphertextHex}\n` +
        `Forged tag       ${attack.forgedTagHex}\n` +
        `Server (holds true H) accepts forgery: ${attack.serverAccepts ? 'VALID' : 'invalid'}.\n\n` +
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
  let forged: { messageBytes: Uint8Array; rawTagHex: string; hmacAttemptHex: string; guessedSecretLength: number } | null = null;
  // Verdicts are per-forgery. They must be dropped whenever a new forgery is
  // made, or the summary would re-render an old server verdict against the NEW
  // guess — claiming "acceptance confirms that guess" for a length that was
  // never submitted.
  let lastRaw: boolean | null = null;
  let lastHmac: boolean | null = null;
  const forgetVerdicts = (): void => {
    lastRaw = null;
    lastHmac = null;
  };

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
      forgetVerdicts();
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
    regenerateDemoSecret();
    captured = null;
    forged = null;
    forgetVerdicts();
    byId<HTMLElement>('le-summary').textContent = '';
    byId<HTMLElement>('le-raw-tag').textContent = '(rotated — capture again)';
    byId<HTMLElement>('le-hmac-tag').textContent = '(rotated — capture again)';
    byId<HTMLElement>('le-forge-output').textContent = '(secret rotated; capture, then forge)';
    setVerdictIdle(byId<HTMLElement>('le-verdict-raw'), 'rotated — recapture');
    setVerdictIdle(byId<HTMLElement>('le-verdict-hmac'), 'rotated — recapture');
    setStatus('Secret rotated to a new hidden length.');
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
        hmacAttemptHex: result.forgedHmacTagAttemptHex,
        guessedSecretLength: result.guessedSecretLength
      };
      // Reveal + populate the structural layout diagram.
      const layout = byId<HTMLElement>('le-layout');
      layout.hidden = false;
      byId<HTMLElement>('le-seg-msg-detail').textContent = captured.message;
      byId<HTMLElement>('le-seg-append-detail').textContent = append;
      // Glue is SHA-256 padding for (guessedSecretLength + message.length) bytes.
      const gluePreview = result.forgedMessageVisible
        .replace(captured.message, '')
        .replace(append, '');
      byId<HTMLElement>('le-seg-glue-detail').textContent =
        (gluePreview || '\\x80\\x00…len').slice(0, 40) + ` (guessed secret = ${result.guessedSecretLength}B)`;

      byId<HTMLElement>('le-forge-output').textContent =
        `Guessed secret length: ${result.guessedSecretLength}\n` +
        `Forged message (visible): ${result.forgedMessageVisible}\n` +
        `Forged message (hex):     ${fmtHex(result.forgedMessageHex, 200)}\n` +
        `Forged tag (broken construction):       ${result.forgedRawTagHex}\n` +
        `Forged tag (HMAC attempt — won't work): ${result.forgedHmacTagAttemptHex}\n`;
      setVerdictIdle(byId<HTMLElement>('le-verdict-raw'), 'forged — submit it');
      setVerdictIdle(byId<HTMLElement>('le-verdict-hmac'), 'forged — submit it');
      // This is a new forgery: the previous servers' verdicts belong to the
      // previous guess and must not be re-attributed to this one.
      forgetVerdicts();
      byId<HTMLElement>('le-summary').textContent =
        `Forged with guessed secret length ${result.guessedSecretLength} — submit it to both servers.`;
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

  function updateLeSummary(rawOk: boolean | null, hmacOk: boolean | null): void {
    if (rawOk !== null) lastRaw = rawOk;
    if (hmacOk !== null) lastHmac = hmacOk;
    const guessed = forged?.guessedSecretLength;
    const parts: string[] = [];
    if (lastRaw === true) parts.push(`✅ BROKEN server accepted the forgery made with secret-length guess ${guessed}; acceptance confirms that guess.`);
    if (lastRaw === false) parts.push(`❌ BROKEN server rejected the forgery made with guess ${guessed}. The actual secret length remains hidden; forge again with a different guess.`);
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
