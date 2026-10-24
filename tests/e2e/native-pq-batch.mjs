// Manual native RPC acceptance: NODE_BIN and SHELL_SDK_ENTRY select installed releases.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { openSync, closeSync } from 'node:fs';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';

assert.ok(process.env.NODE_BIN && process.env.SHELL_SDK_ENTRY,
  'Set NODE_BIN to shell-node and SHELL_SDK_ENTRY to the installed SDK entry');
const binary = resolve(process.env.NODE_BIN);
const entry = resolve(process.env.SHELL_SDK_ENTRY);
const sdk = await import(pathToFileURL(entry).href);
const require = createRequire(pathToFileURL(entry));
const { ml_dsa65 } = await import(pathToFileURL(require.resolve('@noble/post-quantum/ml-dsa.js')).href);
const directory = await mkdtemp(join(tmpdir(), 'shell-pq-batch-'));
const password = randomBytes(24).toString('hex');
const passwordFile = join(directory, 'password.txt');
const keyFile = join(directory, 'validator.json');
await writeFile(passwordFile, password, { mode: 0o600 });
const generated = spawnSync(binary, ['key', 'generate', '--algorithm', 'mldsa65',
  '--output', keyFile, '--password-file', passwordFile], { encoding: 'utf8', timeout: 60000 });
assert.equal(generated.status, 0, 'Validator generation failed');
const miner = await sdk.decryptKeystore(JSON.parse(await readFile(keyFile, 'utf8')), password);
const word = n => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(n); return bytes; };
const hex = bytes => '0x' + Buffer.from(bytes).toString('hex');
const pair = ml_dsa65.keygen(randomBytes(32));
const items = [0, 1].map(index => {
  const message = Buffer.from('PQ batch public acceptance ' + index);
  const signature = ml_dsa65.sign(message, pair.secretKey);
  assert.ok(ml_dsa65.verify(signature, message, pair.publicKey));
  return Buffer.concat([word(pair.publicKey.length), pair.publicKey,
    word(message.length), message, signature]);
});
pair.secretKey.fill(0);
const input = Buffer.concat(items);
// RPC calldata is bounded at 128 KiB. A small contract may legitimately build
// the larger precompile input in memory. Repeat two valid tuples 128 times;
// signature uniqueness remains the responsibility of a multisig application.
function wrapper(gas) {
  const code = [];
  const push = value => {
    const bytes = Buffer.from(value.toString(16).padStart(value <= 255 ? 2 : value <= 65535 ? 4 : 6, '0'), 'hex');
    code.push(0x5f + bytes.length, ...bytes);
  };
  push(256); push(0); code.push(0x52);
  for (let index = 0; index < 128; index++) {
    push(input.length); push(0); push(32 + index * input.length); code.push(0x37);
  }
  push(32); push(0); push(4 + 128 * input.length); push(28); push(3); push(gas);
  code.push(0xfa); // STATICCALL, returning the boolean followed by call success.
  push(32); code.push(0x52); push(64); push(0); code.push(0xf3);
  return hex(code);
}
const contracts = [0, 1].map(index => '0x' + (0x12345000000n + BigInt(index)).toString(16).padStart(64, '0'));
const alloc = { [miner.getAddress()]: { balance: '0x3635c9adc5dea00000', nonce: 0, code: null, storage: null } };
contracts.forEach((address, index) => {
  alloc[address] = { balance: '0x0', nonce: 0, code: wrapper(3071999 + index), storage: null };
});
await writeFile(join(directory, 'genesis.json'), JSON.stringify({
  chain_id: 1337, chain_name: 'pq-batch-acceptance', network_type: 'Dev',
  timestamp: Math.floor(Date.now() / 1000) - 120, gas_limit: 50000000,
  extra_data: 'pq-batch-acceptance', alloc, boot_nodes: [],
  consensus: { engine: 'wpoa', authorities: [miner.getAddress()],
    authority_pubkeys: [hex(miner.getPublicKey())], weights: [1], stakes: [],
    block_time_secs: 2, max_future_secs: 300, epoch_length: 0 },
}));
const listener = createServer();
await new Promise((done, fail) => { listener.once('error', fail); listener.listen(0, '127.0.0.1', done); });
const port = listener.address().port;
await new Promise(done => listener.close(done));
const fd = openSync(join(directory, 'node.log'), 'wx');
const child = spawn(binary, ['run', '--datadir', directory, '--keystore', keyFile,
  '--password-file', passwordFile, '--rpc-addr', `127.0.0.1:${port}`,
  '--metrics-addr', '127.0.0.1:0', '--network', 'dev', '--chain-id', '1337',
  '--consensus-engine', 'wpoa', '--db', 'rocksdb', '--storage-profile', 'full',
  '--max-idle-interval', '1209600000'], { stdio: ['ignore', fd, fd] });
closeSync(fd);
let spawnError;
child.once('error', error => { spawnError = error; });
const pause = ms => new Promise(done => setTimeout(done, ms));
let id = 0;
async function rpc(method, params = []) {
  const response = await fetch(`http://127.0.0.1:${port}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(15000),
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
  return response.json();
}
const result = async (method, params) => {
  const response = await rpc(method, params);
  assert.equal(response.error, undefined, JSON.stringify(response.error));
  return response.result;
};
const state = async () => ({
  block: await result('eth_getBlockByNumber', ['latest', false]),
  balance: await result('eth_getBalance', [miner.getAddress(), 'latest']),
  nonce: await result('eth_getTransactionCount', [miner.getAddress(), 'latest']),
});
const call = (to, data) => rpc('eth_call', [{ from: miner.getAddress(), to,
  data: hex(data), gas: '0x2faf080' }, 'latest']);
const one = '1'.padStart(64, '0'), zero = '0'.repeat(64);
try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (spawnError) throw spawnError;
    assert.equal(child.exitCode, null, 'Node exited before RPC readiness');
    try { await result('eth_blockNumber'); ready = true; break; } catch {}
    await pause(100);
  }
  assert.ok(ready, 'RPC readiness timeout');
  const before = await state();
  const precompile = '0x' + '3'.padStart(64, '0');
  for (const count of [1, 2]) {
    assert.equal((await call(precompile, Buffer.concat([word(count), ...items.slice(0, count)]))).result, '0x' + one);
  }
  assert.equal((await call(contracts[1], input)).result, '0x' + one + one,
    '256 signatures succeed at exactly 256 * 12000 forwarded gas');
  const insufficient = await call(contracts[0], input);
  assert.equal(insufficient.error, undefined);
  assert.equal(insufficient.result.slice(-64), zero, 'One less forwarded gas fails the child call');
  const corrupt = Buffer.from(input); corrupt[corrupt.length - 1] ^= 1;
  assert.equal((await call(contracts[1], corrupt)).result, '0x' + zero + one,
    'Invalid signature returns false without reverting the caller');
  assert.ok((await call(precompile, word(257))).error,
    'Over-cap header must reject before tuple decoding; RPC hides the halt classification');
  assert.deepEqual(await state(), before, 'Read-only calls preserve head, root, balance and nonce');
  console.log(JSON.stringify({ passed: true, cases: 6, signatures: 256,
    exactBatchGas: 3072000, readOnly: true }));
} finally {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
    for (let attempt = 0; attempt < 80 && child.exitCode === null && child.signalCode === null; attempt++) await pause(250);
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL'); await new Promise(done => child.once('exit', done));
    }
  }
  assert.ok(child.exitCode !== null || child.signalCode !== null);
}
