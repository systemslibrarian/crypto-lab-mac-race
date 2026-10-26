import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

const cases = [
  {
    name: 'Gray-code offset recurrence replaced by a fresh power',
    file: 'src/pmac/pmac.ts',
    anchor: 'offset = xor(offset, lPower(l, trailingZeroBits(index)));',
    replacement: 'offset = lPower(l, trailingZeroBits(index));',
    // Two non-final blocks are required: at i=1 recurrence and a fresh power
    // are identical. The official 34-byte vector reaches i=2 and separates
    // Offset(2) = L xor (L*x) from the mutant's fresh L*x.
    test: 'PMAC-AES-128 34 bytes',
    unit: true,
  },
  {
    name: 'power-of-two offset exponent is wrong at block 64',
    file: 'src/pmac/pmac.ts',
    anchor: '  return count;\n}',
    replacement: '  return index === 64 ? count - 1 : count;\n}',
    test: 'cross-checks byte arithmetic against a BigInt/noble reference for varied lengths and keys',
    unit: true,
  },
  {
    name: 'lane encryption omits its offset',
    file: 'src/pmac/pmac.ts',
    anchor: 'const input = xor(block, laneOffset);',
    replacement: 'const input = new Uint8Array(block);',
    test: 'PMAC-AES-128 32 bytes',
    unit: true,
  },
  {
    name: 'partial final block loses the 10-star marker',
    file: 'src/pmac/pmac.ts',
    anchor: 'out[block.length] = 0x80;',
    replacement: 'out[block.length] = 0x00;',
    test: 'PMAC-AES-128 3 bytes',
    unit: true,
  },
  {
    name: 'complete final block omits L times x inverse',
    file: 'src/pmac/pmac.ts',
    anchor: "const applyInverse = finalRule === 'correct' ? complete : !complete;",
    replacement: "const applyInverse = finalRule === 'correct' ? false : !complete;",
    test: 'keeps complete and partial final-block rules distinct',
    unit: true,
  },
  {
    name: 'verifier accepts every candidate tag',
    file: 'src/pmac/pmac.ts',
    anchor: 'return equalTag((await pmac2002(key, message)).tag, new Uint8Array(candidateTag));',
    replacement: 'return true;',
    test: 'accepts genuine tags and rejects content, position and final-rule mutations',
    unit: true,
  },
  {
    name: 'PMAC span is replaced by CMAC block count',
    file: 'src/pmac/schedule.ts',
    anchor: 'pmac: { aesWork: blockCount, aesSpan: pmacWaves.length, waves: pmacWaves },',
    replacement: 'pmac: { aesWork: blockCount, aesSpan: blockCount, waves: pmacWaves },',
    test: 'uses equal per-message AES work but exposes the correct dependency span',
    unit: true,
  },
  {
    name: 'wrong-final control silently becomes correct PMAC',
    file: 'src/pmac/pmac.ts',
    anchor: "return computePmac(key, message, 'inverted');",
    replacement: "return computePmac(key, message, 'correct');",
    test: 'wrong complete and partial final-block rules',
  },
  {
    name: 'performance-model warning disappears',
    file: 'src/pmac/panel.ts',
    anchor: '<strong>not a measured multicore speedup</strong>',
    replacement: '<strong>a measured multicore speedup</strong>',
    test: 'variant, standardization and performance boundaries',
  },
  {
    name: 'Q2 superposition-query attack boundary is reversed',
    file: 'src/pmac/panel.ts',
    anchor: '<strong>not Q2-secure</strong>',
    replacement: '<strong>Q2-secure</strong>',
    test: 'variant, standardization and performance boundaries',
  },
];

function run(command, args, extraEnv = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    timeout: 180_000,
    env: { ...process.env, CI: '1', ...extraEnv },
  });
  return { status: result.status, output: `${result.stdout ?? ''}\n${result.stderr ?? ''}` };
}

function requirePass(result, label) {
  if (result.status !== 0) throw new Error(`${label}\n${result.output}`);
}

function describeError(error) {
  return error instanceof Error ? (error.stack ?? error.message) : String(error);
}

function assets() {
  return Object.fromEntries(
    readdirSync('dist/assets')
      .filter((file) => file.endsWith('.js'))
      .sort()
      .map((file) => [file, createHash('sha256').update(readFileSync(`dist/assets/${file}`)).digest('hex')]),
  );
}

const buildHash = () => createHash('sha256').update(JSON.stringify(assets())).digest('hex');

function owning(entry) {
  if (entry.unit) {
    return run('npx', ['vitest', 'run', 'src/pmac/pmac.test.ts', '-t', entry.test]);
  }
  return run(
    'npx',
    ['playwright', 'test', '--project=chromium', 'e2e/pmac.spec.ts', '--grep', entry.test, '--retries=0'],
    { MUTATION_ASSETS: JSON.stringify(assets()) },
  );
}

requirePass(run('npm', ['run', 'build']), 'baseline build failed');
const baseline = buildHash();
for (const entry of cases) {
  const result = owning(entry);
  requirePass(result, `${entry.name}: baseline owning test failed`);
  if (!/1 passed/.test(result.output)) throw new Error(`${entry.name}: owning test did not run exactly once\n${result.output}`);
}
console.log('baseline: unmutated copy PASSES');

const evidence = [];
for (const entry of cases) {
  const source = readFileSync(entry.file, 'utf8');
  if (source.split(entry.anchor).length !== 2) throw new Error(`${entry.name}: expected exactly one mutation site`);
  let failure;
  let sourceDiff = '';
  let mutantHash = baseline;
  let phaseError;
  let restorationError;
  let restoredGreen = false;
  let restoredHash = baseline;
  try {
    writeFileSync(entry.file, source.replace(entry.anchor, entry.replacement));
    sourceDiff = run('git', ['diff', '--', entry.file]).output.trim();
    if (!sourceDiff) throw new Error(`${entry.name}: mutation produced no source diff`);
    if (!entry.unit) {
      requirePass(run('npm', ['run', 'build']), `${entry.name}: mutant build failed`);
      mutantHash = buildHash();
      if (mutantHash === baseline) throw new Error(`${entry.name}: browser mutation did not change built JavaScript`);
    }
    failure = owning(entry);
  } catch (error) {
    phaseError = error;
  } finally {
    try {
      writeFileSync(entry.file, source);
      if (readFileSync(entry.file, 'utf8') !== source) throw new Error(`${entry.name}: source was not restored byte for byte`);
      if (!entry.unit) {
        requirePass(run('npm', ['run', 'build']), `${entry.name}: restored build failed`);
        restoredHash = buildHash();
        if (restoredHash !== baseline) throw new Error(`${entry.name}: restored bundle differs from baseline`);
      }
      const restored = owning(entry);
      requirePass(restored, `${entry.name}: restored owning test failed`);
      if (!/1 passed/.test(restored.output)) throw new Error(`${entry.name}: restored test did not run exactly once`);
      restoredGreen = true;
    } catch (error) {
      restorationError = error;
    }
  }

  if (restorationError) {
    const earlier = phaseError ? `\nEarlier mutation-phase error:\n${describeError(phaseError)}` : '';
    throw new Error(`${entry.name}: clean restoration failed\n${describeError(restorationError)}${earlier}`);
  }
  if (phaseError) throw phaseError;

  const assertionFailure = failure?.status !== 0
    && /AssertionError|Error: expect\(|expect\(received\)|TestError/.test(failure.output)
    && failure.output.includes(entry.test)
    && !failure.output.includes('MUTATION_ASSET_MISMATCH')
    && !failure.output.includes('Process from config.webServer');
  if (!assertionFailure) throw new Error(`${entry.name}: mutant did not fail its named assertion\n${failure?.output ?? '(no output)'}`);

  evidence.push({
    name: entry.name,
    file: entry.file,
    sourceDiff,
    owningTest: entry.test,
    unit: Boolean(entry.unit),
    baselinePassed: true,
    mutantHash,
    assertionFailure: true,
    retries: 0,
    servedAssetGuard: !entry.unit,
    restoredSourceByteForByte: true,
    restoredGreen,
    restoredHash,
  });
  console.log(`${entry.name}: caught by ${entry.test}; restored green`);
}

requirePass(run('npm', ['run', 'build']), 'final restored build failed');
if (buildHash() !== baseline) throw new Error('final restored bundle differs from baseline');
writeFileSync('pmac-mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`all ${cases.length} mutation(s) caught`);
