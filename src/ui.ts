import { avalancheBitFlip, computeHmac } from './hmac';
import { computeCmac } from './cmac';
import { computePoly1305, runKeyReuseAttackDemo } from './poly1305';
import { computeGhash, runGhashReuseAttackDemo } from './ghash';
import { runLengthExtensionDemo } from './lengthext';
import { runTimingDemo } from './timing';

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

function fmtHex(hex: string): string {
  return hex.length > 128 ? `${hex.slice(0, 128)}...` : hex;
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

      <main id="main-content" class="panel-grid" aria-label="MAC demo panels">
        <section class="panel" aria-labelledby="p1-title">
          <div class="panel-head">
            <h2 id="p1-title">Panel 1: HMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED DEFAULT">RECOMMENDED DEFAULT</span>
          </div>
          <label for="hmac-message">Message</label>
          <textarea id="hmac-message" aria-label="HMAC message input">transfer=42&to=bob</textarea>
          <label for="hmac-key">Key (text or hex)</label>
          <input id="hmac-key" aria-label="HMAC key input" value="super-secret-key" />
          <button id="hmac-run" aria-label="Compute HMAC results">Compute HMAC</button>
          <pre id="hmac-output" class="hex" aria-label="HMAC output"></pre>
          <pre id="hmac-avalanche" class="hex" aria-label="HMAC avalanche result"></pre>
          <p class="note">FIPS 198-1: HMAC uses nested hashing with ipad/opad, so length extension against bare SHA-256 does not apply.</p>
        </section>

        <section class="panel" aria-labelledby="p2-title">
          <div class="panel-head">
            <h2 id="p2-title">Panel 2: CMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED for FIPS contexts">RECOMMENDED (FIPS contexts)</span>
          </div>
          <label for="cmac-message">Message</label>
          <textarea id="cmac-message" aria-label="CMAC message input">audit-log-entry</textarea>
          <label for="cmac-key">AES-256 key (64 hex or passphrase)</label>
          <input id="cmac-key" aria-label="CMAC key input" value="fips-demo-key" />
          <button id="cmac-run" aria-label="Compute CMAC">Compute CMAC</button>
          <pre id="cmac-output" class="hex" aria-label="CMAC output"></pre>
          <p class="note">NIST SP 800-38B: derives K1/K2 from AES_K(0^128), applies 10* padding, and XORs final block before last encryption.</p>
        </section>

        <section class="panel" aria-labelledby="p3-title">
          <div class="panel-head">
            <h2 id="p3-title">Panel 3: Poly1305</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED with ChaCha20">RECOMMENDED (always use with ChaCha20)</span>
          </div>
          <label for="poly-message">Message</label>
          <textarea id="poly-message" aria-label="Poly1305 message input">Cryptographic Forum Research Group</textarea>
          <button id="poly-run" aria-label="Compute Poly1305 and run key reuse attack">Run Poly1305 demo</button>
          <pre id="poly-output" class="hex" aria-label="Poly1305 output"></pre>
          <pre id="poly-attack" class="hex" aria-label="Poly1305 key reuse attack result"></pre>
          <p class="note">RFC 8439: Poly1305 must use a unique one-time key per message, usually derived by ChaCha20 with a unique nonce.</p>
        </section>

        <section class="panel" aria-labelledby="p4-title">
          <div class="panel-head">
            <h2 id="p4-title">Panel 4: GHASH</h2>
            <span class="chip chip-warn" aria-label="Status secure only with nonce discipline">SECURE when nonce discipline maintained</span>
          </div>
          <label for="ghash-ciphertext">Ciphertext (hex)</label>
          <textarea id="ghash-ciphertext" aria-label="GHASH ciphertext hex input">0388dace60b6a392f328c2b971b2fe78</textarea>
          <button id="ghash-run" aria-label="Compute GHASH and nonce reuse attack">Run GHASH demo</button>
          <pre id="ghash-output" class="hex" aria-label="GHASH output"></pre>
          <pre id="ghash-attack" class="hex" aria-label="GHASH nonce reuse attack result"></pre>
          <p class="note">NIST SP 800-38D: GHASH is linear in GF(2^128). Reusing a GCM nonce is catastrophic.</p>
        </section>

        <section class="panel" aria-labelledby="p5-title">
          <div class="panel-head">
            <h2 id="p5-title">Panel 5: Length Extension Attack</h2>
            <span class="chip chip-bad" aria-label="Status bare SHA-256 as MAC avoid">bare SHA-256 as MAC = AVOID</span>
          </div>
          <label for="le-message">Original message</label>
          <input id="le-message" aria-label="Original message for length extension" value="comment=10&uid=7" />
          <label for="le-append">Attacker append</label>
          <input id="le-append" aria-label="Appended attacker data" value="&admin=true" />
          <button id="le-run" aria-label="Run length extension attack">Run attack</button>
          <pre id="le-output" class="hex" aria-label="Length extension output"></pre>
          <p class="note">Demonstrates real SHA-256 state restoration from digest output; this is why prefix-MAC with bare SHA-256 is unsafe.</p>
        </section>

        <section class="panel" aria-labelledby="p6-title">
          <div class="panel-head">
            <h2 id="p6-title">Panel 6: MAC Comparison + Timing Attack</h2>
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
          <button id="timing-run" aria-label="Measure timing attack differences">Measure timing</button>
          <div class="table-wrap" aria-label="Timing attack measurements">
            <table>
              <caption class="sr-only">Timing attack demonstration: naive versus constant-time MAC comparison</caption>
              <thead><tr><th>Case</th><th>Naive compare</th><th>Constant-time compare</th></tr></thead>
              <tbody id="timing-rows"></tbody>
            </table>
          </div>
          <p id="timing-summary" class="note"></p>
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
        <p>So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31</p>
      </footer>
      <div id="aria-live" class="sr-only" aria-live="polite" role="status"></div>
    </div>
  `;
  byId<HTMLButtonElement>('hmac-run').addEventListener('click', async () => {
    try {
      const message = byId<HTMLTextAreaElement>('hmac-message').value;
      const key = byId<HTMLInputElement>('hmac-key').value;
      const h256 = await computeHmac(message, key, 'SHA-256');
      const h512 = await computeHmac(message, key, 'SHA-512');
      const avalanche = await avalancheBitFlip(message, key);
      byId<HTMLElement>('hmac-output').textContent =
        `HMAC-SHA-256: ${h256.macHex}\n` +
        `HMAC-SHA-512: ${h512.macHex}\n` +
        `ipad: ${fmtHex(h256.visual.ipadHex)}\n` +
        `opad: ${fmtHex(h256.visual.opadHex)}\n` +
        `inner: ${h256.visual.innerHashHex}\nouter: ${h256.visual.outerHashHex}`;
      byId<HTMLElement>('hmac-avalanche').textContent =
        `Original : ${avalanche.original}\n` +
        `Flip msg : ${avalanche.flippedMessage}\n` +
        `Flip key : ${avalanche.flippedKey}`;
      setStatus('HMAC computed successfully.');
    } catch (error) {
      setStatus(`HMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('cmac-run').addEventListener('click', async () => {
    try {
      const message = byId<HTMLTextAreaElement>('cmac-message').value;
      const key = byId<HTMLInputElement>('cmac-key').value;
      const result = await computeCmac(message, key);
      byId<HTMLElement>('cmac-output').textContent =
        `CMAC tag: ${result.tagHex}\n` +
        `AES key: ${result.details.keyHex}\n` +
        `K1: ${result.details.k1Hex}\nK2: ${result.details.k2Hex}\n` +
        `Padded last block: ${result.details.paddedLastBlockHex}\n` +
        `Final XOR block: ${result.details.finalXorBlockHex}\n` +
        `Chaining: ${result.details.chainingHex.join(' -> ') || '(single-block message)'}`;
      setStatus('CMAC computed successfully.');
    } catch (error) {
      setStatus(`CMAC error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('poly-run').addEventListener('click', () => {
    try {
      const message = byId<HTMLTextAreaElement>('poly-message').value;
      const result = computePoly1305(message);
      const attack = runKeyReuseAttackDemo();
      byId<HTMLElement>('poly-output').textContent =
        `Poly1305 tag: ${result.tagHex}\n` +
        `One-time key: ${result.keyHex}\n` +
        `GF(2^130 - 5) accumulator uses clamped r and nonce-derived keying.`;
      byId<HTMLElement>('poly-attack').textContent =
        `msg1/tag1: ${attack.msg1} -> ${attack.tag1Hex}\n` +
        `msg2/tag2: ${attack.msg2} -> ${attack.tag2Hex}\n` +
        `Recovered weak r: 0x${attack.recoveredRHex}\n` +
        `Forged tag for ${attack.msg3}: ${attack.forgedTagHex}\n` +
        `Forgery valid: ${attack.validForgery ? 'YES' : 'NO'}`;
      setStatus('Poly1305 demo complete.');
    } catch (error) {
      setStatus(`Poly1305 error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('ghash-run').addEventListener('click', async () => {
    try {
      const ciphertextHex = byId<HTMLTextAreaElement>('ghash-ciphertext').value.trim();
      const result = await computeGhash(ciphertextHex);
      const attack = runGhashReuseAttackDemo();
      byId<HTMLElement>('ghash-output').textContent =
        `H = E_K(0^128): ${result.hHex}\n` +
        `GHASH output: ${result.yHex}\n` +
        `Steps: ${result.steps.join(' -> ')}`;
      byId<HTMLElement>('ghash-attack').textContent =
        `Delta C: ${attack.deltaCHex}\n` +
        `Delta T: ${attack.deltaTHex}\n` +
        `Recovered H: ${attack.recoveredHHex}\n` +
        `Forgery valid: ${attack.forgedValid ? 'YES' : 'NO'}\n` +
        `${attack.note}`;
      setStatus('GHASH demo complete.');
    } catch (error) {
      setStatus(`GHASH error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('le-run').addEventListener('click', async () => {
    try {
      const message = byId<HTMLInputElement>('le-message').value;
      const append = byId<HTMLInputElement>('le-append').value;
      const demo = await runLengthExtensionDemo(message, append, 16);
      byId<HTMLElement>('le-output').textContent =
        `Original MAC: ${demo.originalMacHex}\n` +
        `Forged message (hex): ${demo.forgedMessageHex}\n` +
        `Forged MAC: ${demo.forgedMacHex}\n` +
        `Server recomputed: ${demo.verificationMacHex}\n` +
        `Forgery valid: ${demo.valid ? 'YES' : 'NO'}`;
      setStatus('Length extension attack executed.');
    } catch (error) {
      setStatus(`Length extension error: ${(error as Error).message}`, true);
    }
  });

  byId<HTMLButtonElement>('timing-run').addEventListener('click', () => {
    renderTimingRows();
    setStatus('Timing measurements updated.');
  });

  renderTimingRows();
}
