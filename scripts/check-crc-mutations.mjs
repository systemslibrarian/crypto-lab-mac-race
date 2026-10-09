import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const unit = ['npm', ['test', '--', 'src/crc/crc.test.ts']];
const crcPage = ['npx', ['playwright', 'test', 'e2e/claims.spec.ts', '--grep', 'CRC catches noise']];
const hmacPage = ['npx', ['playwright', 'test', 'e2e/claims.spec.ts', '--grep', 'HMAC rejects the same']];

function run([command, args]) {
  return spawnSync(command, args, { cwd: root, encoding: 'utf8', env: { ...process.env, CI: '' } });
}

function requirePass(command, label) {
  const result = run(command);
  if (result.status !== 0) throw new Error(`${label} failed:\n${result.stdout}\n${result.stderr}`);
}

function bundleHash() {
  const file = readdirSync(join(root, 'dist/assets')).find((name) => /^index-.*\.js$/.test(name));
  if (!file) throw new Error('Built JS bundle missing');
  return createHash('sha256').update(readFileSync(join(root, 'dist/assets', file))).digest('hex');
}

requirePass(['npm', ['run', 'build']], 'baseline build');
const baselineHash = bundleHash();
requirePass(unit, 'baseline CRC unit test');
requirePass(crcPage, 'baseline CRC page test');
requirePass(hmacPage, 'baseline HMAC page test');

const cases = [
  ['CRC polynomial', 'src/crc/crc32.ts', 'const POLY = 0xedb88320;', 'const POLY = 0xedb88321;', unit],
  ['receiver inversion', 'src/crc/receiver.ts', 'return crc32(bytes) === (sentCrc >>> 0);', 'return crc32(bytes) !== (sentCrc >>> 0);', crcPage],
  ['missing affine offset', 'src/crc/forge.ts', 'originalCrc ^ crc32(delta) ^ crc32(new Uint8Array(original.length))', 'originalCrc ^ crc32(delta)', crcPage],
  ['accepted forgery painted green', 'src/crc/panel.ts', 'chip.classList.add(`verdict-${kind}`);', "chip.classList.add(kind === 'alarm' ? 'verdict-accept' : `verdict-${kind}`);", crcPage],
  ['missing forced byte', 'src/crc/forge.ts', 'return withPatch;', 'return withPatch.slice(0, -1);', crcPage],
  ['HMAC always rejects', 'src/crc/hmac-receiver.ts', "crypto.subtle.verify('HMAC', key, tag as BufferSource, bytes as BufferSource)", "crypto.subtle.verify('HMAC', key, tag as BufferSource, bytes as BufferSource).then(() => false)", hmacPage],
  ['HMAC always accepts', 'src/crc/hmac-receiver.ts', "crypto.subtle.verify('HMAC', key, tag as BufferSource, bytes as BufferSource)", "crypto.subtle.verify('HMAC', key, tag as BufferSource, bytes as BufferSource).then(() => true)", hmacPage],
  ['key leaked by default', 'src/crc/panel.ts', 'id="crc-key-leaked" type="checkbox"', 'id="crc-key-leaked" type="checkbox" checked', hmacPage],
];

try {
  for (const [label, path, before, after, command] of cases) {
    const file = join(root, path);
    const source = readFileSync(file, 'utf8');
    if (source.split(before).length !== 2) throw new Error(`${label}: expected exactly one mutation site`);
    try {
      writeFileSync(file, source.replace(before, after));
      requirePass(['npm', ['run', 'build']], `${label} mutant build`);
      if (bundleHash() === baselineHash) throw new Error(`${label}: browser bundle did not move`);
      const result = run(command);
      if (result.status === 0) throw new Error(`${label}: test survived the mutant`);
      if (!/FAIL|failed|AssertionError|Error:/.test(result.stdout + result.stderr)) throw new Error(`${label}: failure was not a named test assertion:\n${result.stdout}\n${result.stderr}`);
      process.stdout.write(`caught: ${label}\n`);
    } finally {
      writeFileSync(file, source);
    }
  }
} finally {
  requirePass(['npm', ['run', 'build']], 'restored build');
  if (bundleHash() !== baselineHash) throw new Error('Restored bundle differs from baseline');
}
