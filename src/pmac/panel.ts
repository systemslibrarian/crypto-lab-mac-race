import { cmacBytes } from '../cmac';
import { hex } from '../cbcmac/cbcmac';
import { pmac2002, pmacWrongFinalRuleForLesson, verifyPmac2002, type PmacResult } from './pmac';
import { modelPmacVsCmac, type AesWave } from './schedule';

type Scenario = 'baseline' | 'flip' | 'swap' | 'wrong-final';

export const pmacPanelHtml = `<section class="panel panel-wide pmac-panel" id="p8" aria-labelledby="p8-title">
  <div class="panel-head"><span class="lesson-badge">Lesson 6</span><h2 id="p8-title">PMAC: independent AES lanes</h2><span class="chip chip-ok">Black–Rogaway 2002</span></div>
  <p class="subtitle">PMAC offsets each non-final block before AES, so those AES calls do not depend on one another. Their outputs are XORed with the final block, then one final AES call produces the tag. CMAC performs the same number of per-message AES calls, but each call consumes the previous chaining value.</p>
  <p>This lesson executes the <strong>2002 Black–Rogaway PMAC definition</strong>, not an unnamed PMAC-like construction or a later refinement. The implementation uses AES-256 and a full 128-bit tag over byte-aligned messages. The paper also defines arbitrary bit strings and tag truncation; those interfaces are outside this lesson.</p>

  <div class="pmac-controls">
    <div><label for="pmac-length">Message shape</label><select id="pmac-length"><option value="64">64 bytes · four complete blocks</option><option value="66">66 bytes · four blocks plus a two-byte tail</option></select></div>
    <div><label for="pmac-scenario">Experiment</label><select id="pmac-scenario"><option value="baseline">Honest baseline</option><option value="flip">Flip one bit in block 2</option><option value="swap">Swap blocks 1 and 2</option><option value="wrong-final">Use the wrong final-block rule</option></select></div>
    <div><label for="pmac-lanes">Modeled AES lanes</label><select id="pmac-lanes"><option value="1">1 lane</option><option value="2">2 lanes</option><option value="4" selected>4 lanes</option></select></div>
  </div>
  <div class="button-row"><button id="pmac-run">Run PMAC experiment</button><button id="pmac-rotate" class="secondary">Rotate teaching keys</button></div>
  <p id="pmac-status" role="status">Run the baseline or choose a mutation.</p>

  <div id="pmac-results" hidden>
    <div class="pmac-verdicts">
      <div class="pmac-card"><h3>Original tag checked against scenario bytes</h3><span id="pmac-original-verdict" class="verdict verdict-idle" data-accepted="">awaiting experiment</span><p id="pmac-original-note"></p></div>
      <div class="pmac-card"><h3>Scenario candidate under the correct verifier</h3><span id="pmac-candidate-verdict" class="verdict verdict-idle" data-accepted="">awaiting experiment</span><p id="pmac-candidate-note"></p></div>
    </div>

    <div class="pmac-tags hex" role="status" aria-label="Computed PMAC and CMAC tags">
      <p><strong>Public PMAC teaching key</strong><code data-pmac="pmac-key"></code></p>
      <p><strong>Public CMAC teaching key</strong><code data-pmac="cmac-key"></code></p>
      <p><strong>Original PMAC tag</strong><code data-pmac="base-tag"></code></p>
      <p><strong>Scenario candidate tag</strong><code data-pmac="candidate-tag"></code></p>
      <p><strong>CMAC tag on original message</strong><code data-pmac="cmac-tag"></code></p>
    </div>

    <h3>Message blocks used in this run</h3>
    <div class="pmac-block-pair">
      <div><h4>Original</h4><div id="pmac-base-blocks" class="pmac-blocks" data-pmac="base-message"></div></div>
      <div><h4>Scenario</h4><div id="pmac-candidate-blocks" class="pmac-blocks" data-pmac="candidate-message"></div></div>
    </div>

    <h3>Actual PMAC lane inputs and outputs</h3>
    <p class="note">Offsets are prepared from <code>L = AES<sub>K</sub>(0<sup>128</sup>)</code>. Every row below is known before any row's AES output is available, so the AES calls may be scheduled independently. The final AES input waits for their XOR reduction.</p>
    <div class="table-wrap" tabindex="0" role="region" aria-label="PMAC independent AES lane trace">
      <table id="pmac-trace"><caption>Scenario trace from the current run</caption><thead><tr><th scope="col">Block</th><th scope="col">Message</th><th scope="col">Gray-code offset</th><th scope="col">AES input</th><th scope="col">AES output</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="pmac-final hex"><p><strong>L = AES<sub>K</sub>(0<sup>128</sup>)</strong><code data-pmac="l"></code></p><p><strong>L·x<sup>−1</sup></strong><code data-pmac="l-inverse"></code></p><p><strong>Final block rule</strong><span data-pmac="final-rule"></span></p><p><strong>Padded/final block</strong><code data-pmac="padded-final"></code></p><p><strong>XOR checksum</strong><code data-pmac="checksum"></code></p><p><strong>Final AES input</strong><code data-pmac="final-input"></code></p></div>

    <h3>Same message, explicit AES dependency model</h3>
    <p id="pmac-schedule-summary" class="checksum-claim" data-pmac="schedule-summary"></p>
    <div class="pmac-schedules"><div><h4>PMAC waves</h4><ol id="pmac-waves"></ol></div><div><h4>CMAC chain</h4><ol id="cmac-waves"></ol></div></div>
  </div>

  <details class="source-toggle"><summary>Model boundary and sources</summary>
    <p>The work count is exact for the displayed algorithms: both use one AES call per message block, where an empty or partial final block counts as one. Each also derives material with one <code>AES<sub>K</sub>(0<sup>128</sup>)</code> call that may be cached once per key; setup is shown separately and excluded from per-message work/span. PMAC's modeled span is the number of AES scheduling waves with the selected lane limit, followed by its final AES. XOR reduction, offset preparation, API overhead and hardware scheduling are not timed.</p>
    <p>This is a dependency model, <strong>not a measured multicore speedup</strong>. <code>Promise.all</code> expresses that the non-final AES calls have no data dependency; it does not prove that a browser or CPU executes them simultaneously. CMAC and PMAC use separate keys, as independent schemes should. This panel discloses those randomly generated keys as <strong>public test material</strong> so the trace is independently reproducible; it is not an attacker model or a usable authenticity deployment.</p>
    <p>The correct verifier recomputes the exact construction and compares all tag bytes after a public length check. JavaScript does not guarantee constant-time machine code. This teaching implementation is not a production MAC library and does not itself prove the paper's PRF theorem.</p>
    <p>The post-quantum label is model-specific. This lesson gives an attacker ordinary classical MAC queries. Kaplan, Leurent, Leverrier and Naya-Plasencia show a Simon-style forgery against PMAC when the attacker instead receives superposition access to the MAC oracle, so the construction is <strong>not Q2-secure</strong>. That stronger oracle is not implemented here.</p>
    <p>Primary sources: <a href="https://www.cs.ucdavis.edu/~rogaway/papers/pmac.pdf" target="_blank" rel="noopener noreferrer">Black and Rogaway, EUROCRYPT 2002, §§2–5</a>; author-hosted <a href="https://www.cs.ucdavis.edu/~rogaway/ocb/pmac128.txt" target="_blank" rel="noopener noreferrer">PMAC-AES-128</a> and <a href="https://www.cs.ucdavis.edu/~rogaway/ocb/pmac256.txt" target="_blank" rel="noopener noreferrer">PMAC-AES-256 vectors</a>. Rogaway's <a href="https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf" target="_blank" rel="noopener noreferrer">2004 refinements</a> are later variants and are not silently substituted here.</p>
  </details>
</section>`;

const ascending = (length: number): Uint8Array => Uint8Array.from({ length }, (_, index) => index & 0xff);

function scenarioMessage(message: Uint8Array, scenario: Scenario): Uint8Array {
  const out = new Uint8Array(message);
  if (scenario === 'flip') out[16] ^= 1;
  if (scenario === 'swap') {
    out.set(message.slice(16, 32), 0);
    out.set(message.slice(0, 16), 16);
  }
  return out;
}

function blockMarkup(bytes: Uint8Array): string {
  const count = Math.ceil(bytes.length / 16);
  return Array.from({ length: count }, (_, index) => {
    const block = bytes.slice(index * 16, (index + 1) * 16);
    return `<div class="pmac-block"><strong>Block ${index + 1} · ${block.length} byte${block.length === 1 ? '' : 's'}</strong><code>${hex(block)}</code></div>`;
  }).join('');
}

function waveMarkup(waves: AesWave[]): string {
  return waves.map((wave) => `<li data-wave="${wave.round}"><strong>AES scheduling wave ${wave.round}</strong><span>${wave.tasks.map((task) => task.label).join(' + ')}</span></li>`).join('');
}

function paintExpectedVerdict(element: HTMLElement, accepted: boolean, expectedAccepted: boolean): void {
  element.dataset.accepted = String(accepted);
  element.className = `verdict ${accepted === expectedAccepted ? 'verdict-accept' : 'verdict-alarm'}`;
  element.textContent = accepted ? 'ACCEPTED' : 'REJECTED';
}

export function wirePmacPanel(): void {
  const node = <T extends HTMLElement>(id: string): T => document.getElementById(id)! as T;
  const length = node<HTMLSelectElement>('pmac-length');
  const scenario = node<HTMLSelectElement>('pmac-scenario');
  const lanes = node<HTMLSelectElement>('pmac-lanes');
  const status = node('pmac-status');
  const results = node('pmac-results');
  const run = node<HTMLButtonElement>('pmac-run');
  let pmacKey = crypto.getRandomValues(new Uint8Array(32));
  let cmacKey = crypto.getRandomValues(new Uint8Array(32));
  let revision = 0;
  let busy = false;
  const fingerprint = (): string => `${length.value}|${scenario.value}|${lanes.value}`;
  let previous = fingerprint();

  function controls(): void {
    run.disabled = busy;
    node<HTMLButtonElement>('pmac-rotate').disabled = busy;
  }

  function retire(message: string): void {
    revision += 1;
    busy = false;
    results.hidden = true;
    status.textContent = message;
    controls();
  }

  for (const field of [length, scenario, lanes]) field.addEventListener('change', () => {
    const current = fingerprint();
    if (current === previous) return;
    previous = current;
    retire('Inputs changed; all tags, traces and verdicts retired.');
  });

  node<HTMLButtonElement>('pmac-rotate').addEventListener('click', () => {
    pmacKey = crypto.getRandomValues(new Uint8Array(32));
    cmacKey = crypto.getRandomValues(new Uint8Array(32));
    retire('PMAC and CMAC teaching keys rotated; all prior results retired.');
  });

  run.addEventListener('click', async () => {
    if (busy) return;
    const id = ++revision;
    busy = true;
    controls();
    status.textContent = 'Computing real PMAC and CMAC tags…';
    try {
      const selected = scenario.value as Scenario;
      const baseMessage = ascending(Number(length.value));
      const candidateMessage = scenarioMessage(baseMessage, selected);
      const base = await pmac2002(pmacKey, baseMessage);
      const candidate: PmacResult = selected === 'wrong-final'
        ? await pmacWrongFinalRuleForLesson(pmacKey, candidateMessage)
        : await pmac2002(pmacKey, candidateMessage);
      const [originalAccepted, candidateAccepted, cmac] = await Promise.all([
        verifyPmac2002(pmacKey, candidateMessage, base.tag),
        verifyPmac2002(pmacKey, candidateMessage, candidate.tag),
        cmacBytes(cmacKey, baseMessage)
      ]);
      if (id !== revision) return;

      const expectedOriginal = selected === 'baseline' || selected === 'wrong-final';
      const expectedCandidate = selected !== 'wrong-final';
      paintExpectedVerdict(node('pmac-original-verdict'), originalAccepted, expectedOriginal);
      paintExpectedVerdict(node('pmac-candidate-verdict'), candidateAccepted, expectedCandidate);
      node('pmac-original-note').textContent = selected === 'baseline'
        ? 'The untouched message accepts its genuine tag.'
        : selected === 'wrong-final'
          ? 'The message is unchanged, so its original correct tag still accepts.'
          : 'Changing block content or position makes the original tag fail.';
      node('pmac-candidate-note').textContent = selected === 'wrong-final'
        ? 'The same bytes under the inverted final rule produce a tag the correct relation rejects.'
        : 'A freshly computed tag for these exact bytes passes the correct verifier.';

      (document.querySelector('[data-pmac="pmac-key"]') as HTMLElement).textContent = hex(pmacKey);
      (document.querySelector('[data-pmac="cmac-key"]') as HTMLElement).textContent = hex(cmacKey);
      (document.querySelector('[data-pmac="base-tag"]') as HTMLElement).textContent = base.tagHex;
      (document.querySelector('[data-pmac="candidate-tag"]') as HTMLElement).textContent = candidate.tagHex;
      (document.querySelector('[data-pmac="cmac-tag"]') as HTMLElement).textContent = cmac.tagHex;
      node('pmac-base-blocks').innerHTML = blockMarkup(baseMessage);
      node('pmac-candidate-blocks').innerHTML = blockMarkup(candidateMessage);
      node('pmac-base-blocks').dataset.hex = hex(baseMessage);
      node('pmac-candidate-blocks').dataset.hex = hex(candidateMessage);

      node('pmac-trace').querySelector('tbody')!.innerHTML = candidate.details.lanes.map((lane) =>
        `<tr data-pmac-lane="${lane.index}"><th scope="row">${lane.index}</th><td data-field="block">${lane.blockHex}</td><td data-field="offset">${lane.offsetHex}</td><td data-field="input">${lane.inputHex}</td><td data-field="output">${lane.outputHex}</td></tr>`
      ).join('');
      (document.querySelector('[data-pmac="final-rule"]') as HTMLElement).textContent = candidate.details.finalRule;
      (document.querySelector('[data-pmac="l"]') as HTMLElement).textContent = candidate.details.lHex;
      (document.querySelector('[data-pmac="l-inverse"]') as HTMLElement).textContent = candidate.details.lInverseHex;
      (document.querySelector('[data-pmac="padded-final"]') as HTMLElement).textContent = candidate.details.paddedFinalBlockHex;
      (document.querySelector('[data-pmac="checksum"]') as HTMLElement).textContent = candidate.details.checksumHex;
      (document.querySelector('[data-pmac="final-input"]') as HTMLElement).textContent = candidate.details.finalInputHex;

      const schedule = modelPmacVsCmac(baseMessage.length, Number(lanes.value));
      node('pmac-schedule-summary').textContent = `Per-message AES work: PMAC ${schedule.pmac.aesWork}, CMAC ${schedule.cmac.aesWork}. Modeled AES span with ${schedule.lanes} lane${schedule.lanes === 1 ? '' : 's'}: PMAC ${schedule.pmac.aesSpan} wave${schedule.pmac.aesSpan === 1 ? '' : 's'}, CMAC ${schedule.cmac.aesSpan} wave${schedule.cmac.aesSpan === 1 ? '' : 's'}. Key setup: one AES_K(0^128) call for each scheme, cached outside this count.`;
      node('pmac-schedule-summary').dataset.pmacWork = String(schedule.pmac.aesWork);
      node('pmac-schedule-summary').dataset.cmacWork = String(schedule.cmac.aesWork);
      node('pmac-schedule-summary').dataset.pmacSpan = String(schedule.pmac.aesSpan);
      node('pmac-schedule-summary').dataset.cmacSpan = String(schedule.cmac.aesSpan);
      node('pmac-waves').innerHTML = waveMarkup(schedule.pmac.waves);
      node('cmac-waves').innerHTML = waveMarkup(schedule.cmac.waves);

      results.hidden = false;
      status.textContent = selected === 'baseline'
        ? 'Honest baseline verified; the trace and dependency model come from this run.'
        : selected === 'wrong-final'
          ? 'The nonconforming final-rule tag was rejected by the correct PMAC verifier.'
          : 'The original tag was rejected after mutation; a newly computed tag for the changed bytes was accepted.';
    } catch (error) {
      if (id === revision) {
        results.hidden = true;
        status.textContent = error instanceof Error ? error.message : String(error);
      }
    } finally {
      if (id === revision) {
        busy = false;
        controls();
      }
    }
  });
}
