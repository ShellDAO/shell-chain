// Native CLI recovery acceptance using an independently installed SDK.
// NODE_BIN and SHELL_SDK_ENTRY select the actual release and registry package.
import assert from 'node:assert/strict';
import { createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const binary = process.env.NODE_BIN;
const entry = process.env.SHELL_SDK_ENTRY;
const commit = process.env.SOURCE_COMMIT;
assert.ok(binary && entry && /^[0-9a-f]{40}$/.test(commit ?? ''), 'Missing release inputs');
const sdk = await import(pathToFileURL(entry).href);
const sdkRequire = createRequire(pathToFileURL(entry));
const { blake3 } = await import(pathToFileURL(sdkRequire.resolve('@noble/hashes/blake3')).href);
const { ml_dsa65 } = await import(pathToFileURL(sdkRequire.resolve('@noble/post-quantum/ml-dsa.js')).href);
const { slh_dsa_sha2_256f } = await import(pathToFileURL(sdkRequire.resolve('@noble/post-quantum/slh-dsa.js')).href);
const metadata = JSON.parse(await readFile(resolve(dirname(entry), '../package.json'), 'utf8'));
assert.equal(metadata.version, '0.14.0-rc.3', 'Unexpected SDK version');
const directory = await mkdtemp(join(tmpdir(), 'shell-pq-hd-'));
const report = { version: '0.27.13', commit, sdk: metadata.version, commands: [], identities: [] };
const text = s => new TextEncoder().encode(s);
const concat = (...parts) => Buffer.concat(parts.map(p => Buffer.from(p)));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const secrets = [];
async function privateFile(name, value) {
  const file = join(directory, name);
  await writeFile(file, value, { mode: 0o600, flag: 'wx' });
  return file;
}
function run(label, args, success = true) {
  const p = spawnSync(binary, args, { cwd: directory, encoding: 'utf8', timeout: 60_000 });
  assert.ok(p.status !== null && (p.status === 0) === success, `Unexpected CLI result: ${label}`);
  const output = p.stdout + p.stderr;
  assert.ok(secrets.every(s => !output.includes(s)), `Secret output: ${label}`);
  report.commands.push({ label, exitCode: p.status, expectedRejection: !success });
  return output;
}

// PBKDF2 and the published PQ-HD v1 domains/path are evaluated independently
// of SDK mnemonic/HD functions. Only raw PQ key-generation primitives are shared.
function reference(mnemonic, passphrase, algo, account = 0) {
  const canonical = mnemonic.normalize('NFKD').toLowerCase().split(/\p{White_Space}+/u).filter(Boolean).join(' ');
  const seed = pbkdf2Sync(canonical, 'mnemonic' + passphrase.normalize('NFKD'), 2048, 64, 'sha512');
  let node = blake3(seed, { key: blake3(text('Shell-Chain PQ-HD master key v1')), dkLen: 64 });
  const path = [9000, 8888, algo, account, 0, 0];
  for (const index of path) {
    const encoded = Buffer.alloc(4);
    encoded.writeUInt32BE(0x80000000 + index);
    node = blake3(concat(text('Shell-Chain PQ-HD child v1'), [0], node.slice(0, 32), encoded), { key: node.slice(32), dkLen: 64 });
  }
  const label = algo === 1 ? 'ML-DSA-65' : 'SLH-DSA-SHA2-256f';
  const leaf = blake3(node.slice(0, 32), { key: blake3(text(`Shell-Chain PQ-HD ${label} leaf seed v1`)), dkLen: algo === 1 ? 32 : 96 });
  const pair = algo === 1 ? ml_dsa65.keygen(leaf) : slh_dsa_sha2_256f.keygen(leaf);
  const publicKey = '0x' + Buffer.from(pair.publicKey).toString('hex');
  const address = '0x' + Buffer.from(blake3(concat([algo], pair.publicKey))).toString('hex');
  const sdkSeed = sdk.mnemonicToSeed(mnemonic, passphrase);
  assert.ok(Buffer.from(sdkSeed).equals(seed), 'Independent seed mismatch');
  const actual = sdk.deriveAccount(seed, algo === 1 ? 'ml-dsa-65' : 'slh-dsa-sha2-256f', account);
  assert.ok(actual.address === address && '0x' + Buffer.from(actual.publicKey).toString('hex') === publicKey, 'Independent SDK identity mismatch');
  actual.secretKey.fill(0);
  sdkSeed.fill(0);
  seed.fill(0);
  node.fill(0);
  leaf.fill(0);
  pair.secretKey.fill(0);
  return { address, publicKey, path: 'm/' + path.map(n => n + "'").join('/') };
}

const version = run('version', ['version']);
assert.ok(version.includes('shell-cli 0.27.13') && version.includes(`commit: ${commit.slice(0, 8)}`), 'Wrong native source/version');
const password = randomBytes(24).toString('hex');
secrets.push(password);
const passwordFile = await privateFile('password.txt', password);
const generatedPassword = randomBytes(24).toString('hex');
secrets.push(generatedPassword);
const generatedPasswordFile = await privateFile('generated-password.txt', generatedPassword);
const generated = join(directory, 'generated.json');
const generation = run('generate', ['pq-hd', 'generate', '--output', generated, '--password-file', generatedPasswordFile]);
const phrases = generation.split('\n').map(s => s.trim()).filter(s => /^(?:[a-z]+ ){23}[a-z]+$/.test(s));
assert.equal(phrases.length, 1, 'Expected one 24-word recovery phrase');
const mnemonic = phrases[0];
secrets.push(mnemonic);
assert.equal(sdk.validateHdMnemonic(mnemonic), true, 'Invalid generated mnemonic');
const normalized = '\u0085' + mnemonic.toUpperCase().replace(/[A-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + 0xfee0)).replaceAll(' ', '\u0085  ') + '\u0085';
const phraseFile = await privateFile('phrase.txt', normalized);
const invalidPhrase = await privateFile('invalid-phrase.txt', 'invalid recovery phrase');
const passphrase = ' Café㍍ \n';
const passphraseFile = await privateFile('passphrase.txt', passphrase.normalize('NFD'));
secrets.push(normalized, passphrase, passphrase.normalize('NFD'));
for (const value of ['', passphrase]) {
  const seed = pbkdf2Sync(mnemonic, 'mnemonic' + value.normalize('NFKD'), 2048, 64, 'sha512');
  secrets.push(seed.toString('hex'));
  seed.fill(0);
}
const generatedText = await readFile(generated, 'utf8');
const originalSeed = pbkdf2Sync(mnemonic, 'mnemonic', 2048, 64, 'sha512');
assert.ok(!generatedText.includes(mnemonic) && !generatedText.includes(originalSeed.toString('hex')), 'Plain recovery material in generated wallet');
originalSeed.fill(0);

for (const [caseName, phrasePassphrase] of [['empty', ''], ['unicode', passphrase]]) {
  for (const [algo, name] of [[1, 'mldsa65'], [2, 'slhdsa']]) {
    const output = join(directory, `restored-${caseName}-${name}.json`);
    const args = ['pq-hd', 'restore', '--mnemonic-file', phraseFile, '--password-file', passwordFile, '--algo', name, '--output', output];
    if (caseName === 'unicode') args.push('--passphrase-file', passphraseFile);
    const restored = run(`restore-${caseName}-${name}`, args);
    const expected = reference(mnemonic, phrasePassphrase, algo);
    assert.ok(restored.includes(expected.address) && restored.includes(expected.path), 'Wrong restored default identity');
    if (caseName === 'empty' && algo === 1) assert.ok(generation.includes(expected.address), 'Generated/restored wallet changed identity');
    const before = digest(await readFile(output));
    const raw = await readFile(output, 'utf8');
    const seed = pbkdf2Sync(mnemonic, 'mnemonic' + phrasePassphrase.normalize('NFKD'), 2048, 64, 'sha512');
    assert.ok(!raw.includes(mnemonic) && !raw.includes(seed.toString('hex')) && !raw.includes(password), 'Plain recovery material in restored wallet');
    seed.fill(0);
    assert.equal((await stat(output)).mode & 0o777, 0o600, 'Unsafe wallet file mode');
    for (const [derivedAlgo, derivedName] of [[1, 'mldsa65'], [2, 'slhdsa']]) {
      for (const account of [0, 1]) {
        const identity = reference(mnemonic, phrasePassphrase, derivedAlgo, account);
        const result = run(`reload-${caseName}-${name}-${derivedName}-${account}`, ['pq-hd', 'derive', '--keystore', output, '--password-file', passwordFile, '--algo', derivedName, '--account', String(account)]);
        assert.ok(Object.values(identity).every(value => result.includes(value)), 'Encrypted reload changed identity');
        report.identities.push({ case: caseName, restoredAlgo: name, derivedAlgo: derivedName, account, ...identity });
      }
    }
    run(`old-password-rejected-${caseName}-${name}`, ['pq-hd', 'derive', '--keystore', output, '--password-file', generatedPasswordFile], false);
    run(`no-overwrite-${caseName}-${name}`, args, false);
    assert.equal(digest(await readFile(output)), before, 'Rejected operation changed wallet');
  }
}
const rejectedOutput = join(directory, 'invalid.json');
run('invalid-phrase-no-output', ['pq-hd', 'restore', '--mnemonic-file', invalidPhrase, '--password-file', passwordFile, '--output', rejectedOutput], false);
assert.equal(await stat(rejectedOutput).then(() => true, () => false), false, 'Invalid phrase wrote a wallet');
report.passed = true;
report.walletsUnchangedAfterRejections = true;
report.secretsPrinted = false;
if (process.env.PQ_HD_REPORT) await writeFile(process.env.PQ_HD_REPORT, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ passed: true, version: report.version, identities: report.identities.length, commands: report.commands.length }));
