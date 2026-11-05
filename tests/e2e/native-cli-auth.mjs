// Node.js 20+. Uses only built-in modules and isolated Dev1337 test funds.
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, writeFile, symlink } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { createServer } from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const serverBin = resolve(process.env.NODE_BIN ?? 'target/debug/shell-node');
const clientBin = resolve(process.env.CLI_BIN ?? serverBin);
const out = process.env.SHELL_CLI_AUTH_WORKDIR
  ? resolve(process.env.SHELL_CLI_AUTH_WORKDIR)
  : await mkdtemp(join(tmpdir(), 'shell-cli-auth-'));
if (process.env.SHELL_CLI_AUTH_WORKDIR) await mkdir(out);
const source = process.env.SHELL_CLI_AUTH_FIXTURE;
const pw = join(out, 'password.txt'), wallet = join(out, 'wallet.json');
const miner = join(out, 'miner.json'), reader = join(out, 'reader.json');
const observerDir = join(out, 'observer'), producerDir = join(out, 'producer');
const keyFile = join(out, 'rpc-api-key.txt'), wrongFile = join(out, 'wrong-api-key.txt');
const token = randomBytes(32).toString('hex');
const result = { startedAt: new Date().toISOString(), services: [], commands: [], rpc: [], payments: [], controls: [] };
const nodes = new Map();
const scrub = text => text.replaceAll(token, '[REDACTED]');
const save = () => writeFile(join(out, 'runtime.json'), JSON.stringify(result, null, 2));
const pause = ms => new Promise(r => setTimeout(r, ms));
let owner, authority;

function cli(args, label, credential = keyFile, expectSuccess = true, privateOutput = false) {
  const env = { ...process.env };
  delete env.SHELL_RPC_API_KEY_FILE;
  if (credential !== null) env.SHELL_RPC_API_KEY_FILE = credential;
  const p = spawnSync(clientBin, args, { env, encoding: 'utf8', timeout: 30000 });
  result.commands.push({ label, argv: args, keyFile: credential,
    exit_code: p.status, stdout: privateOutput ? '[key output omitted]' : scrub(p.stdout ?? ''), stderr: scrub(p.stderr ?? '') });
  assert.ok(!(p.stdout ?? '').includes(token) && !(p.stderr ?? '').includes(token), 'client must not print API key');
  if (expectSuccess) assert.equal(p.status, 0, `${label}: ${scrub(p.stderr ?? '')}`);
  else assert.ok(p.status !== null && p.status !== 0, `${label} must reject`);
  return p;
}
async function port() {
  const s = createServer(); await new Promise(r => s.listen(0, '127.0.0.1', r));
  const p = s.address().port; await new Promise(r => s.close(r)); return p;
}
async function rpc(node, method, params = [], credential = token) {
  const input = { jsonrpc: '2.0', id: result.rpc.length + 1, method, params };
  const headers = { 'content-type': 'application/json' };
  if (credential !== null) headers.authorization = `Bearer ${credential}`;
  const response = await fetch(node.url, { method: 'POST', headers, body: JSON.stringify(input), signal: AbortSignal.timeout(5000) });
  const text = scrub(await response.text());
  let output; try { output = JSON.parse(text); } catch { output = { nonJsonBody: text }; }
  result.rpc.push({ node: node.name, input, authenticated: credential === token, http: response.status, output });
  if (credential !== token) return response.status;
  assert.equal(response.status, 200); assert.ok(!output.error && !output.nonJsonBody, JSON.stringify(output));
  return output.result;
}
async function start(name, dir, key, bootnode) {
  const rp = await port(), pp = await port();
  const args = ['run', '--datadir', dir, '--keystore', key, '--password-file', pw,
    '--network', 'dev', '--chain-id', '1337', '--consensus-engine', 'wpoa', '--block-time', '1000',
    '--max-idle-interval', '1209600000', '--db', 'rocksdb', '--storage-profile', 'full',
    '--rpc-addr', `127.0.0.1:${rp}`, '--metrics-addr', '127.0.0.1:0', '--rpc-api', 'eth,net,web3,shell,admin',
    '--rpc-rate-limit', '1000', '--p2p', '--p2p-addr', `127.0.0.1:${pp}`, '--rpc-api-key', token];
  if (key === reader) args.push('--node-role', 'prover');
  if (bootnode) args.push('--bootnode', bootnode);
  const log = join(out, `${name}.log`), fd = openSync(log, 'w');
  const child = spawn(serverBin, args, { stdio: ['ignore', fd, fd] }); closeSync(fd);
  const node = { name, child, url: `http://127.0.0.1:${rp}`, p2pPort: pp, log };
  nodes.set(name, node);
  result.services.push({ name, argv: args.map(v => v === token ? '[REDACTED]' : v), pid: child.pid }); await save();
  for (let i = 0; i < 120; i++) {
    assert.equal(child.exitCode, null, 'native server exited before startup');
    try { if (await rpc(node, 'eth_chainId') === '0x539') return node; } catch { /* Wait for listener. */ }
    await pause(100);
  }
  throw Error('native server startup timeout');
}
async function stop(name) {
  const node = nodes.get(name); if (!node) return;
  if (node.child.exitCode === null && node.child.signalCode === null) {
    node.child.kill('SIGTERM'); await new Promise(r => node.child.once('exit', r));
  }
  const exit = { code: node.child.exitCode, signal: node.child.signalCode };
  result.services.find(v => v.pid === node.child.pid).exit = exit;
  nodes.delete(name);
  await writeFile(node.log, scrub(await readFile(node.log, 'utf8'))); await save();
  assert.equal(exit.code, 0, `${name} clean shutdown`);
}
async function state(node) {
  const block = await rpc(node, 'eth_getBlockByNumber', ['latest', false]);
  const final = await rpc(node, 'eth_getBlockByNumber', ['finalized', false]);
  return { number: block.number, hash: block.hash, root: block.stateRoot, finalized: final.hash,
    wallet: await rpc(node, 'eth_getBalance', [owner.address, 'latest']),
    nonce: await rpc(node, 'eth_getTransactionCount', [owner.address, 'latest']),
    pendingNonce: await rpc(node, 'eth_getTransactionCount', [owner.address, 'pending']),
    recipient: await rpc(node, 'eth_getBalance', [result.recipient, 'latest']),
    miner: await rpc(node, 'eth_getBalance', [authority.address, 'latest']),
    pubkey: await rpc(node, 'shell_getPqPubkey', [owner.address]), pool: await rpc(node, 'shell_pendingCount') };
}
function balance(node) {
  const value = cli(['wallet', 'balance', owner.address, '--rpc-url', node.url], 'authenticated wallet balance');
  return BigInt(value.stdout.trim());
}
async function payment(observer, producer, hash, value, before) {
  const until = Date.now() + 90000; let receipt;
  while (!(receipt = await rpc(observer, 'eth_getTransactionReceipt', [hash]))) {
    assert.ok(Date.now() < until, 'signed payment imported'); await pause(250);
  }
  assert.equal(receipt.status, '0x1'); assert.equal(receipt.from, owner.address); assert.equal(receipt.to, result.recipient);
  for (const node of [observer, producer]) {
    while ((await state(node)).finalized !== receipt.blockHash) {
      assert.ok(Date.now() < until, 'both independent nodes finalize'); await pause(250);
    }
    assert.deepEqual(await rpc(node, 'eth_getTransactionReceipt', [hash]), receipt);
  }
  const after = await state(observer); assert.deepEqual(await state(producer), after);
  const tx = await rpc(observer, 'eth_getTransactionByHash', [hash]);
  const block = await rpc(observer, 'eth_getBlockByHash', [receipt.blockHash, false]);
  assert.equal(BigInt(tx.value), value); assert.equal(BigInt(tx.nonce), BigInt(before.nonce));
  const cap = BigInt(tx.maxFeePerGas), quoted = BigInt(block.baseFeePerGas) + BigInt(tx.maxPriorityFeePerGas);
  const price = cap < quoted ? cap : quoted, fee = price * BigInt(receipt.gasUsed);
  assert.equal(BigInt(receipt.effectiveGasPrice), price);
  assert.equal(BigInt(before.wallet) - BigInt(after.wallet), value + fee);
  assert.equal(BigInt(after.recipient) - BigInt(before.recipient), value);
  assert.equal(BigInt(after.nonce), BigInt(before.nonce) + 1n);
  let rewards = 0n;
  for (const h of block.transactions) {
    const t = await rpc(observer, 'eth_getTransactionByHash', [h]);
    if (t.shellType === 'blockGasReward') rewards += BigInt(t.value);
  }
  assert.equal(BigInt(after.miner) - BigInt(before.miner), rewards);
  assert.equal(after.pubkey, '0x' + owner.public_key.replace(/^0x/, '').toLowerCase());
  assert.equal(BigInt(after.pool), 0n); assert.equal(balance(observer), BigInt(after.wallet));
  const queried = cli(['tx', 'receipt', hash, '--rpc-url', observer.url], 'authenticated CLI receipt');
  assert.deepEqual(JSON.parse(queried.stdout), receipt);
  result.payments.push({ hash, value: value.toString(), receipt, tx, fee: fee.toString(), systemReward: rewards.toString(), before, after });
  await save(); return after;
}

try {
  if (source) {
    for (const name of ['password.txt', 'wallet.json', 'miner.json', 'reader.json', 'observer', 'producer']) {
      await cp(join(resolve(source), name), join(out, name), { recursive: true, errorOnExist: true, force: false });
    }
    result.coldCopiedFixture = true;
  } else {
    await mkdir(observerDir); await mkdir(producerDir);
    await writeFile(pw, randomBytes(24).toString('hex'), { mode: 0o600 });
    cli(['--password-file', pw, 'wallet', 'create', '--output', wallet], 'create isolated funded wallet', null, true, true);
    for (const [path, name] of [[miner, 'miner'], [reader, 'reader']]) {
      cli(['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', path], `create ${name}`, null, true, true);
    }
  }
  owner = JSON.parse(await readFile(wallet, 'utf8')); authority = JSON.parse(await readFile(miner, 'utf8'));
  result.recipient = process.env.SHELL_CLI_AUTH_RECIPIENT ?? '0x' + randomBytes(32).toString('hex');
  result.wallet = { address: owner.address, keyType: owner.key_type };
  assert.notEqual(owner.address, authority.address);
  if (!source) {
    const genesis = { chain_id: 1337, chain_name: 'cli-auth', network_type: 'Dev', timestamp: Math.floor(Date.now() / 1000) - 60,
      gas_limit: 30000000, extra_data: 'cli-auth', boot_nodes: [], bloom_activation_height: 0, fee_accounting_activation_height: 0,
      alloc: { [owner.address]: { balance: '0x3635c9adc5dea00000', nonce: 0, code: null, storage: null } },
      consensus: { engine: 'wpoa', authorities: [authority.address], authority_pubkeys: ['0x' + authority.public_key.replace(/^0x/, '')],
        weights: [1], stakes: [], block_time_secs: 1, max_future_secs: 300, epoch_length: 0 } };
    await writeFile(join(observerDir, 'genesis.json'), JSON.stringify(genesis, null, 2));
    await cp(join(observerDir, 'genesis.json'), join(producerDir, 'genesis.json'));
  }
  await writeFile(keyFile, token + '\n', { mode: 0o600 });
  await writeFile(wrongFile, 'incorrect-test-key\n', { mode: 0o600 });
  const observer = await start('observer', observerDir, reader);
  result.before = await state(observer); assert.equal(BigInt(result.before.pool), 0n);
  result.priorReceipts = [];
  for (let n = 1n; n <= BigInt(result.before.number); n++) {
    const b = await rpc(observer, 'eth_getBlockByNumber', ['0x' + n.toString(16), false]);
    for (const h of b.transactions) result.priorReceipts.push({ hash: h, receipt: await rpc(observer, 'eth_getTransactionReceipt', [h]) });
  }
  assert.equal(balance(observer), BigInt(result.before.wallet));
  const nonce = cli(['account', 'nonce', owner.address, '--rpc-url', observer.url], 'authenticated account nonce');
  assert.equal(BigInt(nonce.stdout.trim()), BigInt(result.before.nonce));
  for (const credential of [null, 'incorrect-test-key']) assert.equal(await rpc(observer, 'eth_chainId', [], credential), 401);
  for (const [label, path] of [['missing credential', null], ['wrong credential', wrongFile]]) {
    const p = cli(['wallet', 'balance', owner.address, '--rpc-url', observer.url], label, path, false);
    assert.match(p.stderr, /401/); result.controls.push({ label, rejected: true });
    const send = cli(['--password-file', pw, 'wallet', 'send', '--to', result.recipient,
      '--value', '5', '--keystore', wallet, '--rpc-url', observer.url], label + ' send', path, false);
    assert.match(send.stderr, /401/);
  }
  for (const [name, contents] of [['empty', ''], ['oversized', 'x'.repeat(4097)], ['injection', 'test\r\nInjected: value'], ['non-utf8', Buffer.from([255])]]) {
    const path = join(out, name + '-key'); await writeFile(path, contents, { mode: 0o600 });
    const p = cli(['wallet', 'balance', owner.address, '--rpc-url', observer.url], name, path, false);
    assert.match(p.stderr, /SHELL_RPC_API_KEY_FILE/); result.controls.push({ label: name, rejected: true });
  }
  if (process.platform !== 'win32') {
    const path = join(out, 'symlink-key'); await symlink(keyFile, path);
    const p = cli(['wallet', 'balance', owner.address, '--rpc-url', observer.url], 'symlink', path, false);
    assert.match(p.stderr, /SHELL_RPC_API_KEY_FILE/); result.controls.push({ label: 'symlink', rejected: true });
  }
  assert.deepEqual(await state(observer), result.before);
  const sent = cli(['--password-file', pw, 'wallet', 'send', '--to', result.recipient, '--value', '43', '--keystore', wallet, '--rpc-url', observer.url], 'authenticated default wallet send43');
  const first = sent.stdout.trim(); assert.match(first, /^0x[0-9a-f]{64}$/);
  const pending = await state(observer); assert.equal(BigInt(pending.nonce), BigInt(result.before.nonce));
  assert.equal(BigInt(pending.pendingNonce), BigInt(result.before.nonce) + 1n); assert.equal(BigInt(pending.pool), 1n);
  const info = await rpc(observer, 'admin_nodeInfo');
  const producer = await start('producer', producerDir, miner, `/ip4/127.0.0.1/tcp/${observer.p2pPort}/p2p/${info.id}`);
  const other = await rpc(producer, 'admin_nodeInfo'); assert.notEqual(info.id, other.id); result.peerIdentities = [info.id, other.id];
  const afterFirst = await payment(observer, producer, first, 43n, result.before);
  const second = cli(['--password-file', pw, 'wallet', 'send', '--to', result.recipient, '--value', '47', '--keystore', wallet, '--rpc-url', observer.url], 'authenticated default wallet send47').stdout.trim();
  assert.match(second, /^0x[0-9a-f]{64}$/);
  result.after = await payment(observer, producer, second, 47n, afterFirst);
  assert.equal(BigInt(result.after.recipient), BigInt(result.before.recipient) + 90n);
  assert.equal(BigInt(result.after.nonce), BigInt(result.before.nonce) + 2n);
  for (const p of [...result.priorReceipts, ...result.payments]) assert.deepEqual(await rpc(observer, 'eth_getTransactionReceipt', [p.hash]), p.receipt);
  assert.deepEqual(await state(observer), result.after);
  await stop('observer'); const reopened = await start('reopened', observerDir, reader);
  assert.deepEqual(await state(reopened), result.after); assert.equal(balance(reopened), BigInt(result.after.wallet));
  for (const p of [...result.priorReceipts, ...result.payments]) assert.deepEqual(await rpc(reopened, 'eth_getTransactionReceipt', [p.hash]), p.receipt);
  result.passed = true;
} catch (error) {
  result.error = scrub(String(error)); process.exitCode = 1;
} finally {
  for (const name of [...nodes.keys()]) { try { await stop(name); } catch (error) { result.error ??= scrub(String(error)); process.exitCode = 1; } }
  result.nodesStopped = nodes.size === 0; result.finishedAt = new Date().toISOString(); await save();
  console.log(JSON.stringify({ passed: result.passed, error: result.error, artifactDirectory: out, services: result.services.map(v => v.exit) }));
}
