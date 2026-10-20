import { checkBlocks, hex, lengthBlock, LENGTH_MISMATCH, NOT_BLOCK_ALIGNED, TAG_MISMATCH, type ChainStep, type Verification } from './cbcmac';
import { spliceOne, spliceTwo } from './forge';
import { makeLessonOracles, type Variant } from './oracle';

export const CBC_NEGATIVE = "A valid raw CBC-MAC tag does not authenticate the message's length: when the receiver accepts more than one length, every check this verifier performs passes on a message nobody tagged.";
const variants = ['raw', 'fixed', 'prepended', 'cmac'] as const;
const names = { raw: 'Accepts any length — vulnerable', fixed: 'Agreed length', prepended: 'Length prepended', cmac: 'CMAC' };
const safe = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const encode = (text: string) => new TextEncoder().encode(text);
export const cbcMacPanelHtml = `<section class="panel panel-wide cbcmac-panel" id="p7" aria-labelledby="p7-title">
  <div class="panel-head"><span class="lesson-badge">Lesson 4</span><h2 id="p7-title">Raw CBC-MAC: fixed length only</h2><span class="chip chip-warn">Length is part of the contract</span></div>
  <p class="subtitle">CBC-MAC chains AES across a message and keeps the last block as its tag. It is a sound construction when sender and receiver agree on one fixed length. A receiver that accepts different lengths lets an observed tag become a tool for forging a longer message.</p>
  <p>Start with the agreed-length receiver: zero IV, whole 16-byte blocks, no padding. Katz–Lindell Construction 4.9 and Theorem 4.10 apply when <strong>every message has the same agreed length</strong>, under the block-cipher security assumption. The receiver accepting any length below is deliberately vulnerable.</p>
  <div class="cbc-inputs"><div><label for="cbc-message">Message m · UTF-8 bytes</label><input id="cbc-message" value="PAY ALICE 0010!!" maxlength="128" title="Raw CBC-MAC refuses empty messages; with no blocks its tag would just be the IV."></div><div><label for="cbc-attack">Attacker's recipe</label><select id="cbc-attack"><option value="one">One classical tag · one-block m</option><option value="two">Two classical tags · m and m′</option></select></div><div><label for="cbc-agreed">Receiver's agreed length</label><select id="cbc-agreed">${Array.from({ length: 16 }, (_, i) => `<option value="${16 * (i + 1)}">${i + 1} block${i ? 's' : ''} · ${16 * (i + 1)} bytes</option>`).join('')}</select></div></div>
  <div id="cbc-second" hidden><label for="cbc-prime">Second message m′ · UTF-8, whole blocks</label><input id="cbc-prime" value="PAY BOB 9999!!!!PAY BOB 9999!!!!" maxlength="128"></div>
  <div class="button-row"><button id="cbc-tag">Get tag</button><button id="cbc-forge" disabled>Forge</button><button id="cbc-rotate" class="secondary">Rotate hidden keys</button></div>
  <p id="cbc-status" role="status">Get an authentic tag before building a forgery.</p>
  <div id="cbc-public" class="hex stepper" role="status"></div><div id="cbc-forged" role="status"></div>
  <div class="cbc-verifiers">${variants.map(v => `<div class="cbc-verifier" id="cbc-card-${v}"><h3>${names[v]}</h3><span class="verdict verdict-idle" id="cbc-verdict-${v}" role="status">awaiting experiment</span><div id="cbc-checks-${v}"></div></div>`).join('')}</div>
  <div id="cbc-negative" class="checksum-claim" hidden></div>
  <div id="cbc-chain-area" hidden><h3>Watch the chaining values converge</h3><p>The inserted block cancels t. From that point the forged chain repeats the honest target chain, ending at the same tag. The verifier computes this trace after submission; the attacker only used the public tags.</p><div class="button-row"><button id="cbc-next">Next chaining step</button><button id="cbc-all">Reveal all chaining steps</button></div><div class="table-wrap hex stepper" tabindex="0" role="region" aria-label="CBC-MAC honest and forged chaining values"><table id="cbc-chain"><caption>Forged chain, aligned with the honest target after the splice</caption><thead><tr><th scope="col">Forged block</th><th scope="col">Message block</th><th scope="col">AES input after XOR</th><th scope="col">Forged chain value</th><th scope="col">Honest target block</th><th scope="col">Honest AES input</th><th scope="col">Honest chain value</th></tr></thead><tbody></tbody></table></div></div>
  <p class="note">Length prepending encodes the message's <strong>byte length as one unsigned 16-byte big-endian block</strong>, then MACs that block and the message. <a href="#p2">The next lesson shows CMAC's K1/K2 final-block fix.</a></p>
  <details class="source-toggle"><summary>What the comparison proves</summary><p>All four receivers recompute their tags from the submitted bytes. The fixed-length receiver shares the raw receiver's key so only the length rule differs. The prepended and CMAC experiments have separate hidden AES-256 keys: exposing a raw signing oracle under a CMAC key would create an additional cross-protocol attack. Their cards first test the exact raw forged bytes and raw tag, then test the same splice recipe using their <em>own</em> authentic tags. Their honest tags are checked before either attack.</p><p>If the agreed receiver length is changed to the forged length, it accepts: the sender already issued a tag of another length. Both ends must enforce the same fixed length. This demonstrates the scope of the theorem, not a contradiction.</p><p>Raw CBC-MAC rejects empty and unaligned messages without padding. Tag comparison uses a fixed-work byte loop after a public length check; JavaScript does not guarantee constant-time machine code.</p></details>
  <p>The classical splice needs variable-length messages and one or two ordinary tags. <a href="https://systemslibrarian.github.io/crypto-lab-simon-period/">Simon's Period</a> instead forges fixed-length two-block CBC-MAC using <strong>superposition queries</strong>, outside the classical-query theorem.</p>
  <p class="note">Sources: Katz–Lindell §4.4.1, Figure 4.2, Exercises 4.13–4.15; <a href="https://www.rfc-editor.org/rfc/rfc4493">RFC 4493</a>; <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf">NIST CMAC examples</a>. Random-IV, output-all-chaining-values and length-appended forgeries are extension seams, not experiments on this page.</p>
</section>`;

type Capture = { m: Uint8Array; prime: Uint8Array; two: boolean; tags: Record<Variant, Uint8Array>; targets: Record<Variant, Uint8Array>; honest: Record<Variant, Verification>; targetTrace: ChainStep[] };
export function wireCbcMacPanel(): void {
  const node = <T extends HTMLElement>(id: string) => document.getElementById(id)! as T;
  const message = node<HTMLInputElement>('cbc-message'), prime = node<HTMLInputElement>('cbc-prime'), attack = node<HTMLSelectElement>('cbc-attack'), agreed = node<HTMLSelectElement>('cbc-agreed');
  const status = node('cbc-status'); let oracles = makeLessonOracles(() => Number(agreed.value));
  let revision = 0, busy = false, capture: Capture | null = null, chain: ChainStep[] = [], traceShown = 0;
  const fingerprint = () => [message.value, prime.value, attack.value, agreed.value].join('|'); let previous = fingerprint();
  function chip(v: Variant, kind: 'idle' | 'accept' | 'alarm', label: string): void { const el = node(`cbc-verdict-${v}`); el.className = `verdict verdict-${kind}`; el.textContent = label; }
  function controls(): void { node<HTMLButtonElement>('cbc-tag').disabled = busy; node<HTMLButtonElement>('cbc-forge').disabled = busy || !capture; }
  function retire(why: string): void { revision++; busy = false; capture = null; chain = []; traceShown = 0; status.textContent = why; for (const v of variants) { chip(v, 'idle', 'inputs changed — run again'); node(`cbc-checks-${v}`).textContent = ''; } node('cbc-public').textContent = ''; node('cbc-forged').textContent = ''; node('cbc-negative').hidden = true; node('cbc-chain-area').hidden = true; controls(); }
  function blockCells(bytes: Uint8Array, prefix: string, offset = -1): string {
    return `<div class="cbc-blocks">${Array.from({ length: bytes.length / 16 }, (_, i) => { const b = bytes.slice(16 * i, 16 * (i + 1)); return `<div class="cbc-block"><strong>${prefix} ${i + 1}${i === offset ? ' · inserted XOR block' : ''}</strong><code>${hex(b)}</code><small>${safe(Array.from(b, x => x >= 32 && x < 127 ? String.fromCharCode(x) : '·').join(''))}</small></div>`; }).join('')}</div>`;
  }
  function paintTrace(): void {
    if (!capture) return;
    const prefixCount = capture.m.length / 16;
    node('cbc-chain').querySelector('tbody')!.innerHTML = chain.slice(0, traceShown).map((step, i) => { const j = i - prefixCount, target = capture!.targetTrace[j]; return `<tr data-cbc-step="${i}"><th scope="row">${i + 1}</th><td>${hex(step.block)}</td><td>${hex(step.aesInput)}</td><td data-cbc="chain-value">${hex(step.output)}</td><td>${target ? j + 1 : 'before splice'}</td><td>${target ? hex(target.aesInput) : '—'}</td><td data-cbc="honest-value">${target ? hex(target.output) : '—'}</td></tr>`; }).join('');
    node<HTMLButtonElement>('cbc-next').disabled = traceShown >= chain.length;
  }
  async function run(action: (id: number) => Promise<void>): Promise<void> {
    if (busy) return; const id = ++revision; busy = true; controls(); status.textContent = 'Computing real AES tags…';
    try { await action(id); } catch (error) { if (id === revision) status.textContent = error instanceof Error ? error.message : String(error); }
    finally { if (id === revision) { busy = false; controls(); } }
  }
  for (const field of [message, prime, attack, agreed]) for (const event of ['input', 'change']) field.addEventListener(event, () => { const current = fingerprint(); if (current === previous) return; previous = current; node('cbc-second').hidden = attack.value !== 'two'; retire('Inputs changed; tags, forged bytes and verifier verdicts retired.'); });
  node('cbc-rotate').addEventListener('click', () => { try { oracles = makeLessonOracles(() => Number(agreed.value)); retire('Hidden keys rotated; all tags and verdicts retired.'); } catch { retire('Key generation failed; reload before trying another experiment.'); node<HTMLButtonElement>('cbc-tag').disabled = true; } });
  node('cbc-tag').addEventListener('click', () => void run(async id => {
    const m = encode(message.value), two = attack.value === 'two', other = two ? encode(prime.value) : m;
    checkBlocks(m); checkBlocks(other); if (m.length > 128 || other.length > 128) throw new Error('Each message is limited to 128 UTF-8 bytes.');
    if (!two && m.length !== 16) throw new Error('The one-tag recipe needs exactly 16 message bytes; choose two tags for a multi-block first message.');
    const local = oracles, tags = {} as Record<Variant, Uint8Array>, targets = {} as Record<Variant, Uint8Array>, honest = {} as Record<Variant, Verification>;
    for (const v of ['raw', 'prepended', 'cmac'] as const) { tags[v] = await local[v].mac(m); targets[v] = two ? await local[v].mac(other) : new Uint8Array(tags[v]); }
    tags.fixed = new Uint8Array(tags.raw); targets.fixed = new Uint8Array(targets.raw);
    for (const v of variants) honest[v] = await local[v].verify(m, tags[v]);
    const target = two ? await local.raw.verify(other, targets.raw) : honest.raw;
    if (id !== revision) return;
    capture = { m, prime: other, two, tags, targets, honest, targetTrace: target.steps! };
    node('cbc-public').innerHTML = `<p>Attacker's raw-CBC-MAC queries: <strong data-cbc="queries">${two ? 2 : 1}</strong>. The attacker receives these tags, never a key.</p>${blockCells(m, 'm block')}<p>Tag t: <code data-cbc="tag">${hex(tags.raw)}</code></p>${two ? `${blockCells(other, 'm′ block')}<p>Tag t′: <code data-cbc="target-tag">${hex(targets.raw)}</code></p>` : ''}`;
    node('cbc-forged').textContent = ''; node('cbc-chain-area').hidden = true; node('cbc-negative').hidden = true;
    for (const v of variants) { const result = honest[v]; chip(v, result.accepted ? 'accept' : 'idle', result.accepted ? '✓ honest tag verified' : 'Sender/receiver length disagreement'); node(`cbc-checks-${v}`).innerHTML = `<p>Honest input: ${m.length} bytes; ${result.code}.</p>`; }
    status.textContent = `${two ? 'Two' : 'One'} raw tag${two ? 's' : ''} observed. Independent prepended/CMAC control tags also verified. Press Forge.`;
  }));
  node('cbc-forge').addEventListener('click', () => void run(async id => {
    if (!capture) throw new Error('Get authentic tags first.');
    const runCapture = capture, local = oracles, { m, prime: other, tags, targets, two } = runCapture;
    const forged = two ? spliceTwo(m, tags.raw, other) : spliceOne(m, tags.raw), submitted = targets.raw;
    const checks = {} as Record<Variant, Verification>, own = {} as Record<'prepended' | 'cmac', { forged: Uint8Array; result: Verification }>;
    for (const v of variants) checks[v] = await local[v].verify(forged, submitted);
    for (const v of ['prepended', 'cmac'] as const) { const candidate = two ? spliceTwo(m, tags[v], other) : spliceOne(m, tags[v]); own[v] = { forged: candidate, result: await local[v].verify(candidate, targets[v]) }; }
    if (id !== revision) return;
    node('cbc-forged').innerHTML = `<h3>Forged message: ${two ? 'm ‖ (m′₁ XOR t) ‖ the rest of m′' : 'm ‖ (m XOR t)'}</h3>${blockCells(forged, 'forged block', m.length / 16)}<p>Exact forged bytes: <code data-cbc="forged">${hex(forged)}</code></p><p>Submitted raw tag: <code data-cbc="submitted">${hex(submitted)}</code>. The attacker never requested a tag for this longer message.</p>`;
    for (const v of variants) {
      const result = checks[v], reason = result.code === LENGTH_MISMATCH ? 'wrong length' : result.code === TAG_MISMATCH ? 'tag mismatch' : result.code === NOT_BLOCK_ALIGNED ? 'block alignment' : result.code;
      chip(v, result.accepted ? 'alarm' : 'accept', result.accepted ? '✕ ACCEPTED — FORGED' : `✓ rejected — ${reason}`);
      let html = `<p>Same forged bytes (${forged.length} bytes), same submitted raw tag. ${v === 'fixed' ? `Agreed length: ${agreed.value} bytes.` : ''}</p>`;
      if (result.expected) html += `<p>Receiver recomputed: <code data-cbc="expected">${hex(result.expected)}</code></p>`;
      if (v === 'raw') html += `<p data-cbc="raw-checks">Block alignment: ${forged.length % 16 === 0 ? 'PASS' : 'FAIL'}; tag equality: ${result.accepted ? 'PASS' : 'FAIL'}.</p>${result.accepted ? '<strong data-cbc="negative-heading">TAG VALID — AND FORGED</strong>' : ''}`;
      if (v === 'fixed' && result.accepted) html += '<p>The receiver accepted two lengths across the protocol: the sender tagged another length. Agreement must constrain both ends.</p>';
      if (v === 'prepended') html += `<p>Length block for forged bytes: <code data-cbc="length-block">${hex(lengthBlock(forged.length))}</code></p>`;
      if (v === 'prepended' || v === 'cmac') { const attempt = own[v]; html += `<div class="cbc-own"><h4>Repeat the recipe with this scheme's own tags</h4><p>Authentic t: <code data-cbc="own-tag">${hex(tags[v])}</code></p><p>Authentic target tag: <code data-cbc="own-target">${hex(targets[v])}</code></p><p>Own-oracle forged bytes: <code data-cbc="own-forged">${hex(attempt.forged)}</code></p><p class="verdict verdict-${attempt.result.accepted ? 'alarm' : 'accept'}" data-cbc="own-verdict">${attempt.result.accepted ? '✕ ACCEPTED — FORGED' : '✓ rejected — tag mismatch'}</p><p>Honest tag verification: ${runCapture.honest[v].accepted ? 'PASS' : 'FAIL'}.</p></div>`; }
      node(`cbc-checks-${v}`).innerHTML = html;
    }
    node('cbc-negative').textContent = CBC_NEGATIVE; node('cbc-negative').hidden = !checks.raw.accepted;
    chain = checks.raw.steps ?? []; traceShown = 1; node('cbc-chain-area').hidden = !chain.length; paintTrace();
    status.textContent = 'All receiver decisions came from recomputed MACs. Reveal the chaining steps to inspect the cancellation.';
  }));
  node('cbc-next').addEventListener('click', () => { traceShown = Math.min(chain.length, traceShown + 1); paintTrace(); });
  node('cbc-all').addEventListener('click', () => { traceShown = chain.length; paintTrace(); });
}
