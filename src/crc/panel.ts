import { crc32, crcHex } from './crc32';
import { crcReceiverAccepts } from './receiver';
import { forceCrc, repairCrc } from './forge';
import { createHmacReceiver } from './hmac-receiver';

const encode = (message: string) => new TextEncoder().encode(message);
const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const checksumPanelHtml = `
  <section class="panel panel-wide checksum-panel" id="p0" aria-labelledby="p0-title">
    <div class="panel-head"><span class="lesson-badge">Lesson 1</span><h2 id="p0-title">Checksum vs MAC</h2><span class="chip chip-warn">CRC-32 is public</span></div>
    <p class="subtitle">Send the same payment through one CRC receiver. First noise changes it, then an attacker does. Watch when a valid checksum stops meaning an authentic message.</p>
    <div class="checksum-inputs">
      <div><label for="crc-message">Original message</label><input id="crc-message" value="PAY $0010 TO ALICE" /><p class="note">Original CRC-32: <code id="crc-original">00000000</code></p></div>
      <div><label for="crc-altered">Attacker's same-length message</label><input id="crc-altered" value="PAY $9000 TO ALICE" /><p id="crc-length-error" class="checksum-error" role="status"></p></div>
    </div>
    <div class="checksum-steps">
      <div class="checksum-step" id="crc-step1">
        <h3>1. Accident: noise flips bits</h3>
        <div class="checksum-controls"><label for="crc-bit-count">Random bit flips: <output id="crc-bit-value">1</output></label><input id="crc-bit-count" type="range" min="1" max="8" value="1" /><label class="checkbox-label"><input id="crc-burst" type="checkbox" /> Burst up to 32 adjacent bits</label><p id="crc-burst-note" class="note" hidden>Burst mode chooses 1–32 adjacent bits; the slider is paused.</p></div>
        <button id="crc-accident">Send corrupted message</button>
        <p class="note">Noise doesn't know the checksum, so it can't fix it.</p>
        <div id="crc-bytes1" class="checksum-bytes" aria-live="polite"></div><p id="crc-check1" class="checksum-check"></p>
        <div><span id="crc-verdict1" class="verdict verdict-idle" role="status">awaiting experiment</span><span id="crc-working1" class="checksum-working" hidden>✓ working as intended</span></div>
      </div>
      <div class="checksum-step" id="crc-step2">
        <h3>2. Deliberate change, old CRC</h3><button id="crc-naive">Send with old CRC</button>
        <p class="note">So far, so good.</p><div id="crc-bytes2" class="checksum-bytes" aria-live="polite"></div><p id="crc-check2" class="checksum-check"></p>
        <div><span id="crc-verdict2" class="verdict verdict-idle" role="status">awaiting experiment</span><span id="crc-working2" class="checksum-working" hidden>✓ working as intended</span></div>
      </div>
      <div class="checksum-step" id="crc-step3">
        <h3>3. Deliberate change, CRC repaired</h3><button id="crc-repair">Recompute and send CRC</button>
        <p class="note">The checksum is public arithmetic. Whoever edits, re-adds.</p><div id="crc-bytes3" class="checksum-bytes" aria-live="polite"></div><p id="crc-check3" class="checksum-check"></p>
        <span id="crc-verdict3" class="verdict verdict-idle" role="status">awaiting experiment</span>
        <div class="checksum-force"><h4>3b. Force any CRC you like</h4><label for="crc-target">Target CRC (exactly 8 hex digits)</label><input id="crc-target" value="deadbeef" inputmode="text" maxlength="8" /><button id="crc-force">Append 4 computed bytes</button>
          <p id="crc-target-error" class="checksum-error" role="status"></p><div id="crc-bytes3b" class="checksum-bytes" aria-live="polite"></div><p id="crc-check3b" class="checksum-check"></p><span id="crc-verdict3b" class="verdict verdict-idle" role="status">awaiting experiment</span></div>
      </div>
      <div class="checksum-step" id="crc-step4">
        <h3>4. Same change against HMAC-SHA-256</h3>
        <label for="crc-hmac-attempt">Attacker's tag attempt</label><select id="crc-hmac-attempt"><option value="old">Reuse original tag</option><option value="guess">Recompute with a guessed key</option></select>
        <label for="crc-guessed-key">Guessed key (used only for the second option)</label><input id="crc-guessed-key" value="my-guess" />
        <label class="checkbox-label checksum-leak"><input id="crc-key-leaked" type="checkbox" /> What if the key leaked?</label>
        <button id="crc-hmac">Send to HMAC receiver</button>
        <p class="note" id="crc-hmac-caption">To fix the tag you need the key, and the attacker doesn't have it.</p><div id="crc-bytes4" class="checksum-bytes" aria-live="polite"></div><p id="crc-check4" class="checksum-check"></p>
        <details class="source-toggle" id="crc-hmac-trace"><summary>Inspect HMAC tags</summary><p class="checksum-check">Original tag: <code id="crc-tag-original"></code></p><p class="checksum-check">Submitted tag: <code id="crc-tag-submitted"></code></p></details>
        <div><span id="crc-verdict4" class="verdict verdict-idle" role="status">awaiting experiment</span><span id="crc-working4" class="checksum-working" hidden>✓ working as intended</span></div>
        <button id="crc-rotate-key" class="secondary">Rotate hidden HMAC key</button>
      </div>
    </div>
    <p class="checksum-claim">CRC-32 detects accidental corruption; it does not detect deliberate changes, because anyone can recompute it.</p>
    <p class="checksum-claim">HMAC is only as strong as the secrecy of its key. HMAC does not provide confidentiality or replay protection.</p>
    <details class="source-toggle" id="crc-explainer"><summary>Why the repair works</summary>
      <p>CRC treats bits as polynomial coefficients over <span class="gloss" tabindex="0" role="note" aria-label="GF(2): a field with two elements, 0 and 1; addition is XOR"><span class="gloss-term">GF(2)</span><span class="gloss-pop" aria-hidden="true">A field with two elements, 0 and 1; addition is XOR.</span></span>. For equal-length byte strings, CRC-32 is affine because of its initial register and final XOR:</p>
      <p><code>crc(m′) = crc(m) ⊕ crc(Δ) ⊕ crc(0ⁿ)</code>, with <code>Δ = m ⊕ m′</code>. The three terms below appear after step 3.</p>
      <p id="crc-affine" class="checksum-check">Run step 3 to see the three terms.</p>
      <p>For 3b, the four appended bytes supply 32 adjustable bits. Inverting their effect on the CRC register lets us reach any chosen 32-bit value, as described by Stigge and colleagues in <a href="https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2006-05/SAR-PR-2006-05_.pdf" target="_blank" rel="noreferrer">Reversing CRC, section 4</a>.</p>
      <p><a href="#p4">GHASH</a> also has exploitable algebra after nonce reuse, but its hash subkey is secret. CRC needs no key at all.</p>
    </details>
    <p class="note">CRC parameters and check value: <a href="https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32-iso-hdlc" target="_blank" rel="noreferrer">CRC RevEng, CRC-32/ISO-HDLC</a>. The HMAC receiver uses the same changed bytes as step 3.</p>
    <p class="links" role="group" aria-label="Related checksum and MAC lessons">Explore: <a href="#p4">GHASH</a> · <a href="https://systemslibrarian.github.io/crypto-lab-hash-zoo/" target="_blank" rel="noreferrer">Hash Zoo</a> · <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">Babel Hash</a> · <a href="https://systemslibrarian.github.io/crypto-lab-poly1305-mac/" target="_blank" rel="noreferrer">Poly1305 MAC</a> · <a href="https://systemslibrarian.github.io/crypto-lab-timing-oracle/" target="_blank" rel="noreferrer">Timing Oracle</a></p>
  </section>`;

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing ${id}`);
  return el as T;
}

function setChip(id: string, kind: 'idle' | 'reject' | 'alarm', label: string): void {
  const chip = byId<HTMLElement>(id);
  chip.classList.remove('verdict-idle', 'verdict-reject', 'verdict-accept', 'verdict-alarm');
  chip.classList.add(`verdict-${kind}`);
  chip.textContent = label;
}

function showBytes(id: string, before: Uint8Array, after: Uint8Array): void {
  const root = byId<HTMLElement>(id);
  root.textContent = '';
  for (const [label, bytes] of [['before', before], ['after', after]] as const) {
    const line = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = `${label}: `;
    line.append(name);
    const strip = document.createElement('span');
    strip.className = 'checksum-byte-strip';
    strip.dataset.hex = hex(bytes);
    for (let i = 0; i < bytes.length; i += 1) {
      const cell = document.createElement('span');
      const hexLabel = document.createElement('span');
      hexLabel.textContent = bytes[i]!.toString(16).padStart(2, '0');
      cell.append(hexLabel);
      const diff = (before[i] ?? 0) ^ (after[i] ?? 0);
      if (label === 'after' && (diff || i >= before.length)) {
        cell.className = 'checksum-byte-changed';
        cell.title = i >= before.length ? 'appended byte' : `changed bits: ${diff.toString(2).padStart(8, '0')}`;
        const bitMarks = document.createElement('small');
        bitMarks.className = 'checksum-bit-marks';
        bitMarks.textContent = i >= before.length ? 'NEW BYTE' : Array.from({ length: 8 }, (_, bit) => ((diff >>> (7 - bit)) & 1) ? '↑' : '·').join('');
        bitMarks.setAttribute('role', 'img');
        bitMarks.setAttribute('aria-label', i >= before.length ? 'appended byte' : `changed bit mask ${diff.toString(2).padStart(8, '0')}`);
        cell.append(bitMarks);
      }
      strip.append(cell);
    }
    if (bytes.length === 0) strip.textContent = '(empty)';
    line.append(strip);
    root.append(line);
  }
}

function showCrc(id: string, actual: number, sent: number): void {
  const el = byId<HTMLElement>(id);
  el.textContent = '';
  const actualSpan = document.createElement('span');
  actualSpan.dataset.actual = crcHex(actual);
  actualSpan.textContent = crcHex(actual);
  const sentSpan = document.createElement('span');
  sentSpan.dataset.sent = crcHex(sent);
  sentSpan.textContent = crcHex(sent);
  el.append('Receiver computes ', actualSpan, '; sent CRC ', sentSpan, '.');
}

export function wireChecksumPanel(): void {
  const originalInput = byId<HTMLInputElement>('crc-message');
  const alteredInput = byId<HTMLInputElement>('crc-altered');
  const keyLeaked = byId<HTMLInputElement>('crc-key-leaked');
  const bitCount = byId<HTMLInputElement>('crc-bit-count');
  const burst = byId<HTMLInputElement>('crc-burst');
  const attemptSelect = byId<HTMLSelectElement>('crc-hmac-attempt');
  const guessedKeyInput = byId<HTMLInputElement>('crc-guessed-key');
  let receiver = createHmacReceiver();
  let hmacRevision = 0;
  let lastOriginal = originalInput.value;
  let lastAltered = alteredInput.value;
  const original = () => encode(originalInput.value);
  const altered = () => encode(alteredInput.value);
  const updateOriginalCrc = () => { byId<HTMLElement>('crc-original').textContent = crcHex(crc32(original())); };
  const retireSteps = (suffixes: readonly string[]) => {
    for (const suffix of suffixes) {
      setChip(`crc-verdict${suffix}`, 'idle', 'inputs changed — run again');
      byId<HTMLElement>(`crc-bytes${suffix}`).textContent = '';
      byId<HTMLElement>(`crc-check${suffix}`).textContent = '';
      if (suffix === '3') byId<HTMLElement>('crc-affine').textContent = 'Run step 3 to see the three terms.';
      if (suffix === '4') {
        hmacRevision += 1;
        byId<HTMLElement>('crc-tag-original').textContent = '';
        byId<HTMLElement>('crc-tag-submitted').textContent = '';
      }
      if (suffix === '1' || suffix === '2' || suffix === '4') byId<HTMLElement>(`crc-working${suffix}`).hidden = true;
    }
  };
  const retireAll = () => retireSteps(['1', '2', '3', '3b', '4']);
  const updateHmacCaption = () => {
    byId<HTMLElement>('crc-hmac-caption').textContent = keyLeaked.checked
      ? 'With the leaked key, the attacker can compute a matching tag. The receiver cannot tell who sent it.'
      : "To fix the tag you need the key, and the attacker doesn't have it.";
  };
  const updateAttemptControls = () => {
    attemptSelect.disabled = keyLeaked.checked;
    guessedKeyInput.disabled = keyLeaked.checked || attemptSelect.value !== 'guess';
  };
  const readyAlteration = (): [Uint8Array, Uint8Array] | null => {
    const a = original();
    const b = altered();
    const error = byId<HTMLElement>('crc-length-error');
    if (a.length !== b.length) {
      error.textContent = 'The affine shortcut needs equal byte lengths; 3b shows how length changes are handled.';
      alteredInput.title = error.textContent;
      return null;
    }
    error.textContent = '';
    alteredInput.removeAttribute('title');
    return [a, b];
  };
  originalInput.addEventListener('input', () => {
    if (originalInput.value === lastOriginal) return;
    lastOriginal = originalInput.value;
    updateOriginalCrc();
    readyAlteration();
    retireAll();
  });
  alteredInput.addEventListener('input', () => {
    if (alteredInput.value === lastAltered) return;
    lastAltered = alteredInput.value;
    readyAlteration();
    retireAll();
  });
  bitCount.addEventListener('input', () => { byId<HTMLElement>('crc-bit-value').textContent = bitCount.value; retireSteps(['1']); });
  burst.addEventListener('change', () => {
    bitCount.disabled = burst.checked;
    byId<HTMLElement>('crc-burst-note').hidden = !burst.checked;
    retireSteps(['1']);
  });
  byId<HTMLInputElement>('crc-target').addEventListener('input', () => retireSteps(['3b']));
  attemptSelect.addEventListener('change', () => { updateAttemptControls(); retireSteps(['4']); });
  guessedKeyInput.addEventListener('input', () => retireSteps(['4']));
  keyLeaked.addEventListener('change', () => { updateHmacCaption(); updateAttemptControls(); retireSteps(['4']); });
  byId<HTMLButtonElement>('crc-rotate-key').addEventListener('click', () => { receiver = createHmacReceiver(); retireAll(); });
  updateOriginalCrc();
  updateHmacCaption();
  updateAttemptControls();

  byId<HTMLButtonElement>('crc-accident').addEventListener('click', () => {
    const a = original();
    if (a.length === 0) { setChip('crc-verdict1', 'idle', 'Add message bytes before flipping bits.'); return; }
    const b = a.slice();
    const total = a.length * 8;
    const random = (limit: number) => crypto.getRandomValues(new Uint32Array(1))[0]! % limit;
    if (burst.checked) {
      const length = 1 + random(Math.min(32, total));
      const start = random(total - length + 1);
      for (let bit = start; bit < start + length; bit += 1) b[bit >>> 3]! ^= 1 << (bit & 7);
    } else {
      const positions = new Set<number>();
      while (positions.size < Math.min(Number(bitCount.value), total)) positions.add(random(total));
      for (const bit of positions) b[bit >>> 3]! ^= 1 << (bit & 7);
    }
    const sent = crc32(a);
    showBytes('crc-bytes1', a, b);
    showCrc('crc-check1', crc32(b), sent);
    const accepted = crcReceiverAccepts(b, sent);
    setChip('crc-verdict1', accepted ? 'alarm' : 'reject', accepted ? '⚠ CRC VALID — collision' : '✗ CORRUPTION CAUGHT');
    byId<HTMLElement>('crc-working1').hidden = accepted;
  });

  byId<HTMLButtonElement>('crc-naive').addEventListener('click', () => {
    const pair = readyAlteration(); if (!pair) return;
    const [a, b] = pair; const sent = crc32(a);
    showBytes('crc-bytes2', a, b); showCrc('crc-check2', crc32(b), sent);
    const accepted = crcReceiverAccepts(b, sent);
    setChip('crc-verdict2', accepted ? 'alarm' : 'reject', accepted ? '⚠ CRC VALID — old checksum matched' : '✗ REJECTED');
    byId<HTMLElement>('crc-working2').hidden = accepted;
  });

  byId<HTMLButtonElement>('crc-repair').addEventListener('click', () => {
    const pair = readyAlteration(); if (!pair) return;
    const [a, b] = pair; const oldCrc = crc32(a); const sent = repairCrc(a, b, oldCrc);
    showBytes('crc-bytes3', a, b); showCrc('crc-check3', crc32(b), sent);
    const accepted = crcReceiverAccepts(b, sent);
    setChip('crc-verdict3', accepted ? 'alarm' : 'reject', accepted ? '⚠ CRC VALID — AND FORGED' : '✗ REJECTED');
    const delta = a.map((byte, i) => byte ^ b[i]!);
    byId<HTMLElement>('crc-affine').textContent = `${crcHex(oldCrc)} ⊕ ${crcHex(crc32(delta))} ⊕ ${crcHex(crc32(new Uint8Array(a.length)))} = ${crcHex(sent)} (receiver: ${crcHex(crc32(b))})`;
  });

  byId<HTMLButtonElement>('crc-force').addEventListener('click', () => {
    const input = byId<HTMLInputElement>('crc-target').value.trim();
    const error = byId<HTMLElement>('crc-target-error');
    if (!/^[0-9a-fA-F]{8}$/.test(input)) { error.textContent = 'Target CRC must be exactly 8 hex digits.'; setChip('crc-verdict3b', 'idle', 'invalid target'); return; }
    error.textContent = '';
    const a = altered(); const target = parseInt(input, 16) >>> 0; const b = forceCrc(a, target);
    showBytes('crc-bytes3b', a, b); showCrc('crc-check3b', crc32(b), target);
    setChip('crc-verdict3b', crcReceiverAccepts(b, target) ? 'alarm' : 'reject', crcReceiverAccepts(b, target) ? '⚠ CRC VALID — AND FORGED' : '✗ REJECTED');
  });

  byId<HTMLButtonElement>('crc-hmac').addEventListener('click', async () => {
    const pair = readyAlteration(); if (!pair) return;
    const [a, b] = pair;
    const revision = hmacRevision;
    const sessionPromise = receiver;
    const leaked = keyLeaked.checked;
    const attemptType = attemptSelect.value;
    const guessText = guessedKeyInput.value;
    const session = await sessionPromise;
    const genuine = await session.sign(a);
    let attempt = genuine;
    if (leaked) {
      const stolenKey = await crypto.subtle.importKey('raw', session.leakKeyForDemo() as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      attempt = new Uint8Array(await crypto.subtle.sign('HMAC', stolenKey, b as BufferSource));
    }
    else if (attemptType === 'guess') {
      const guessedKey = encode(guessText || '(empty guess)');
      const guess = await crypto.subtle.importKey('raw', guessedKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      attempt = new Uint8Array(await crypto.subtle.sign('HMAC', guess, b as BufferSource));
    }
    const accepted = await session.verify(b, attempt);
    const control = await session.verify(a, genuine);
    if (revision !== hmacRevision) return;
    showBytes('crc-bytes4', a, b);
    byId<HTMLElement>('crc-check4').textContent = `Genuine original control: ${control ? 'ACCEPTED' : 'REJECTED'}. Changed message with submitted tag: ${accepted ? 'ACCEPTED' : 'REJECTED'}.`;
    byId<HTMLElement>('crc-tag-original').textContent = hex(genuine);
    byId<HTMLElement>('crc-tag-submitted').textContent = hex(attempt);
    setChip('crc-verdict4', accepted ? 'alarm' : 'reject', accepted ? '⚠ TAG VALID — AND FORGED' : '✗ REJECTED');
    byId<HTMLElement>('crc-working4').hidden = accepted;
  });
}
