#!/usr/bin/env node
// Real TCP/RocksDB acceptance for certified offline enforcement and restart.
// Requires Node 20+ and `cargo build -p shell-cli --features libp2p`.
// Run: node tests/e2e/native-offline-network.mjs
// Add --full for 100 real misses, epoch suspension and authenticated recovery.
// The full run takes about 30–60 minutes; no threshold or clock is shortened.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { openSync, closeSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const full = process.argv.includes('--full');
assert.ok(process.argv.slice(2).every(arg => arg === '--full'), 'Only --full is supported');
const binary = resolve(process.env.NODE_BIN ?? fileURLToPath(new URL('../../target/debug/shell-node', import.meta.url)));
const directory = await mkdtemp(join(tmpdir(), 'shell-offline-network-'));
const result = { startedAt: new Date().toISOString(), directory, binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), processes: [], blocks: [], phases: [], scope: full ? '100 real assigned misses, native epoch suspension/recovery, TCP quorum, new peer catch-up and physical RocksDB restart.' : 'One real assigned miss, TCP weighted quorum, RocksDB import and physical restart; threshold remains 100 and is not exercised here.' };
const pause = ms => new Promise(done => setTimeout(done, ms));
const save = () => writeFile(join(directory, 'result.json'), JSON.stringify(result, null, 2));
const password = join(directory, 'password.txt');
await writeFile(password, randomBytes(24).toString('hex'), { mode: 0o600 });
const keys = [];
for (let i = 0; i < 3; i++) {
  const path = join(directory, `validator-${i}.json`);
  const generated = spawnSync(binary, ['--password-file', password, 'key', 'generate', '--algorithm', 'mldsa65', '--output', path], { encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const key = JSON.parse(await readFile(path, 'utf8'));
  keys.push({ path, address: key.address, publicKey: '0x' + key.public_key });
}
const initial = '0xd3c21bcecceda1000000';
const genesis = { chain_id: 1337, chain_name: 'offline-network-acceptance', network_type: 'Dev', timestamp: Math.floor(Date.now() / 1000), gas_limit: 50000000, extra_data: 'offline-network-acceptance', alloc: Object.fromEntries(keys.map(key => [key.address, { balance: initial, nonce: 0, code: null, storage: null }])), boot_nodes: [], consensus: { engine: 'wpoa', authorities: keys.map(key => key.address), authority_pubkeys: keys.map(key => key.publicKey), weights: [1, 1, 3], stakes: [], block_time_secs: 2, max_future_secs: 300, epoch_length: 10 }, offline_enforcement: { activation_height: 1, epoch_length: 10, block_time_secs: 2, heartbeat_interval_secs: 600 } };
for (const i of [0, 1, 2]) {
  await mkdir(join(directory, `node-${i}`));
  await writeFile(join(directory, `node-${i}`, 'genesis.json'), JSON.stringify(genesis));
}
async function unusedPort() {
  const listener = createServer();
  await new Promise((done, fail) => { listener.once('error', fail); listener.listen(0, '127.0.0.1', done); });
  const port = listener.address().port;
  await new Promise(done => listener.close(done));
  return port;
}
const ports = [await unusedPort(), await unusedPort(), await unusedPort()];
assert.equal(new Set(ports).size, 3);
const urls = ports.map(port => `http://127.0.0.1:${port}`);
const children = [];
let requestId = 0;
async function rpc(i, method, params = []) {
  const response = await fetch(urls[i], { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++requestId, method, params }), signal: AbortSignal.timeout(10000) });
  assert.ok(response.ok, `${method}: HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) throw Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
async function until(label, action, timeout = 90000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    for (const child of children.filter(Boolean)) assert.equal(child.exitCode, null, 'node exited unexpectedly');
    try { const value = await action(); if (value) return value; } catch (error) { last = error; }
    await pause(250);
  }
  throw Error(`${label}: timeout${last ? ': ' + last.message : ''}`);
}
async function stop() {
  await Promise.all(children.filter(Boolean).map(async child => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    const end = Date.now() + 20000;
    while (child.exitCode === null && child.signalCode === null && Date.now() < end) await pause(100);
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await new Promise(done => child.once('exit', done));
    }
    const record = result.processes.find(record => record.pid === child.pid);
    if (record) Object.assign(record, { stoppedAt: new Date().toISOString(), exitCode: child.exitCode, signal: child.signalCode });
  }));
  children.length = 0;
}
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
  result.exitCode = signal === 'SIGINT' ? 130 : 143;
  result.interrupted = signal;
  result.finishedAt = new Date().toISOString();
  stop().then(save).finally(() => process.exit(result.exitCode));
});
async function start(i, phase, bootnode) {
  const authority = [0, 2, 1][i];
  const log = join(directory, `${phase}-${i}.log`);
  const args = ['run', '--datadir', join(directory, `node-${authority}`), '--keystore', keys[authority].path, '--password-file', password, '--rpc-addr', `127.0.0.1:${ports[i]}`, '--metrics-addr', '127.0.0.1:0', '--network', 'dev', '--chain-id', '1337', '--consensus-engine', 'wpoa', '--block-time', '2000', '--max-idle-interval', '600', '--node-role', 'validator', '--db', 'rocksdb', '--storage-profile', 'full', '--rpc-api', 'eth,net,web3,shell', '--p2p', '--p2p-addr', '127.0.0.1:0', '--log-level', 'info'];
  if (bootnode) args.push('--bootnode', bootnode);
  const fd = openSync(log, 'wx', 0o600);
  const child = spawn(binary, args, { stdio: ['ignore', fd, fd] });
  closeSync(fd);
  children[i] = child;
  result.processes.push({ pid: child.pid, phase, authority: keys[authority].address, args, log, startedAt: new Date().toISOString() });
  await save();
  await until('node startup', () => rpc(i, 'eth_chainId').then(value => { assert.equal(value, '0x539'); return true; }), 40000);
  return until('public P2P address', async () => (await readFile(log, 'utf8')).match(/Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[A-Za-z0-9]+)/)?.[1], 10000);
}
async function connect(phase) {
  const bootnode = await start(0, phase);
  await start(1, phase, bootnode);
  await until('two TCP peers', async () => BigInt(await rpc(0, 'net_peerCount')) > 0n && BigInt(await rpc(1, 'net_peerCount')) > 0n);
}
const registry = '0x' + '0'.repeat(63) + '1';
let validatorSlot;
async function offline(i, tag = 'latest') {
  const raw = await rpc(i, 'eth_getStorageAt', [registry, validatorSlot, tag]);
  const padded = raw.slice(2).padStart(64, '0');
  return [0, 1, 2, 3].map(index => Number(BigInt('0x' + padded.slice(index * 16, (index + 1) * 16))));
}
async function send(i, nonce, to = keys[1].address, data) {
  const authority = [0, 2, 1][i];
  const args = ['--password-file', password, 'tx', 'send', '--keystore', keys[authority].path, '--rpc-url', urls[i], '--chain-id', '1337', '--nonce', String(nonce), '--gas-limit', data ? '150000' : '21000', '--to', to, '--value', data ? '0' : '1'];
  if (data) args.push('--data', data);
  return new Promise((done, fail) => {
    const child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => stdout += data);
    child.stderr.on('data', data => stderr += data);
    child.once('error', fail);
    child.once('exit', code => {
      if (code !== 0) return fail(Error(`tx send ${code}: ${stderr}`));
      const hash = stdout.match(/0x[0-9a-fA-F]{64}/)?.[0];
      if (!hash) return fail(Error('CLI returned no transaction hash'));
      result.transaction = { hash, args, submittedAt: new Date().toISOString() };
      done(hash);
    });
  });
}
async function confirmed(i, to = keys[1].address, data) {
  const authority = [0, 2, 1][i];
  const nonce = Number(BigInt(await rpc(i, 'eth_getTransactionCount', [keys[authority].address, 'latest'])));
  const hash = await send(i, nonce, to, data);
  const receipt = await until('live transfer/governance confirmation', async () => {
    const receipts = await Promise.all([0, 1].map(peer => rpc(peer, 'eth_getTransactionReceipt', [hash])));
    if (!receipts.every(Boolean)) return false;
    assert.deepEqual(receipts[1], receipts[0]);
    return receipts[0];
  }, 120000);
  assert.equal(receipt.status, '0x1', `transaction ${hash} failed`);
  const tag = receipt.blockNumber;
  const blocks = await Promise.all([0, 1].map(peer => rpc(peer, 'eth_getBlockByNumber', [tag, true])));
  assert.equal(blocks[1].hash, blocks[0].hash);
  assert.equal(blocks[1].stateRoot, blocks[0].stateRoot);
  const states = await Promise.all([0, 1].map(peer => offline(peer, tag)));
  assert.deepEqual(states[1], states[0]);
  const proofs = blocks[0].transactions.filter(tx => tx.shellType === 'timeoutEvidence').map(tx => JSON.parse(Buffer.from(tx.input.slice(2), 'hex').toString('utf8')));
  const absentProofs = proofs.filter(proof => proof.context.proposer === keys[1].address);
  for (const proof of absentProofs) {
    assert.deepEqual(proof.signers.map(signer => signer.address).sort(), [keys[0].address, keys[2].address].sort(), 'A1+C3 are both needed for a real weighted timeout quorum');
    assert.equal(proof.context.block_number, Number(BigInt(tag)));
  }
  const record = { height: Number(BigInt(tag)), hash: blocks[0].hash, stateRoot: blocks[0].stateRoot, miner: blocks[0].miner, certifiedAbsentMisses: absentProofs.length, receipt, offline: states[0] };
  result.blocks.push(record);
  await save();
  return record;
}
async function fullLifecycle() {
  let last = result.blocks.at(-1);
  let state = await offline(0);
  let transfers = 1;
  let certifiedMisses = 1;
  const deadline = Date.now() + 2 * 60 * 60 * 1000;
  while (state[0] < 100) {
    assert.ok(Date.now() < deadline, 'full lifecycle exceeded two hours');
    last = await confirmed(1);
    transfers++;
    assert.ok(last.offline[0] >= state[0] && last.offline[0] <= state[0] + 1);
    state = last.offline;
    certifiedMisses += last.certifiedAbsentMisses;
    assert.equal(state[0], certifiedMisses, 'every consecutive miss has its actual quorum certificate');
    if (state[0] < 100) assert.deepEqual(state.slice(1), [0, 0, 0]);
  }
  assert.equal(state[0], 100);
  const incident = state[1];
  assert.equal(incident, Math.floor(last.height / 10) + 1, 'suspension is scheduled at the next common epoch');
  const boundary = incident * 10;
  while (last.height < boundary) { last = await confirmed(1); transfers++; }
  for (const i of [0, 1]) {
    assert.deepEqual(await rpc(i, 'shell_getValidatorStatus', [keys[1].address]), result.initialValidator, 'suspension preserves base membership, weight and stake');
    const committee = await rpc(i, 'shell_consensusInfo');
    assert.ok(!committee.validators.some(v => v.address === keys[1].address && v.weight > 0), 'offline member must have no active weight');
    assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[1].address, last.receipt.blockNumber])), BigInt(initial) + BigInt(transfers), 'suspension preserves funds');
  }
  result.phases.push({ phase: '100 assigned misses and common-epoch suspension', boundary, state, certifiedMisses });
  await save();
  const hashName = async name => rpc(0, 'web3_sha3', ['0x' + Buffer.from(name).toString('hex')]);
  const setSlot = await hashName('shell:offline-state:v1:authorities:');
  const set = await rpc(0, 'eth_getStorageAt', [registry, setSlot, 'latest']);
  const selector = (await hashName('recoverValidator(address,uint64,bytes32)')).slice(2, 10);
  const calldata = '0x' + selector + keys[1].address.slice(2) + BigInt(incident).toString(16).padStart(64, '0') + set.slice(2);
  last = await confirmed(0, registry, calldata);
  assert.equal(last.offline[2], 0, 'A1 alone is below strict weighted recovery quorum');
  const minorityHeight = last.height;
  last = await confirmed(1, registry, calldata);
  const recoveryEpoch = Math.floor(last.height / 10) + 1;
  assert.deepEqual(last.offline, [100, incident, recoveryEpoch, 0]);
  result.phases.push({ phase: 'authenticated recovery vote', minorityHeight, approvedHeight: last.height, recoveryEpoch });
  await save();
  // A previously offline physical process catches up from genesis while masked.
  const firstLog = result.processes.find(p => p.phase === 'initial' && p.authority === keys[0].address).log;
  const bootnode = (await readFile(firstLog, 'utf8')).match(/Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[A-Za-z0-9]+)/)?.[1];
  assert.ok(bootnode);
  await start(2, 'returning', bootnode);
  await until('returning physical node catches up', async () => (await rpc(2, 'eth_getBlockByNumber', [last.receipt.blockNumber, false]))?.hash === last.hash, 120000);
  assert.deepEqual(await offline(2, last.receipt.blockNumber), last.offline);
  while (last.height < recoveryEpoch * 10) { last = await confirmed(1); transfers++; }
  assert.deepEqual(last.offline, [0, 0, 0, 0]);
  let returnedProposal = false;
  const recoveryBoundary = last.height;
  for (let n = 0; n < 10 && !returnedProposal; n++) {
    last = await confirmed(1); transfers++;
    const block = await rpc(0, 'eth_getBlockByNumber', [last.receipt.blockNumber, false]);
    returnedProposal = block.miner === keys[1].address;
  }
  assert.ok(returnedProposal, 'recovered physical validator must actually propose a finalized transfer block');
  // The recovered proposer legitimately earns the submitted transaction's
  // effective gas fee. Derive the expected credit from user receipts, rather
  // than treating earned fees as an offline balance mutation.
  const earnedFees = result.blocks.filter(block => block.miner === keys[1].address).reduce((total, block) => total + BigInt(block.receipt.gasUsed) * BigInt(block.receipt.effectiveGasPrice), 0n);
  assert.ok(earnedFees > 0n, 'the returning proposer earned real transaction fees');
  const restoredBalance = BigInt(initial) + BigInt(transfers) + earnedFees;
  for (const i of [0, 1, 2]) {
    await until('restored committee, import and finality', async () => {
      const block = await rpc(i, 'eth_getBlockByNumber', ['finalized', false]);
      return block && Number(BigInt(block.number)) >= last.height;
    });
    assert.deepEqual(await offline(i, last.receipt.blockNumber), [0, 0, 0, 0]);
    assert.deepEqual(await rpc(i, 'shell_getValidatorStatus', [keys[1].address]), result.initialValidator);
    assert.equal((await rpc(i, 'eth_getBlockByNumber', [last.receipt.blockNumber, false])).hash, last.hash);
    assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[1].address, last.receipt.blockNumber])), restoredBalance);
  }
  result.recoveredProposerFees = '0x' + earnedFees.toString(16);
  result.fullBalance = '0x' + restoredBalance.toString(16);
  result.fullTip = last;
  result.fullTransfers = transfers;
  result.phases.push({ phase: 'returning B proposes after epoch recovery', recoveryBoundary, proposedHeight: last.height, hash: last.hash });
  await save();
}
try {
  await connect('initial');
  // Standard hashing RPC only derives the published native storage key; the
  // expected counter comes from the assigned-miss rule, not a runtime helper.
  const keyBytes = Buffer.concat([Buffer.from('shell:offline-state:v1:validator:'), Buffer.from(keys[1].address.slice(2), 'hex')]);
  validatorSlot = await rpc(0, 'web3_sha3', ['0x' + keyBytes.toString('hex')]);
  assert.deepEqual(await offline(0), [0, 0, 0, 0]);
  result.initialValidator = await rpc(0, 'shell_getValidatorStatus', [keys[1].address]);
  assert.equal(result.initialValidator.weight, 1);
  const hash = await send(1, 0);
  await save();
  const receipt = await until('transfer confirmation on both peers', async () => {
    const receipts = await Promise.all([0, 1].map(i => rpc(i, 'eth_getTransactionReceipt', [hash])));
    if (!receipts.every(Boolean)) return false;
    assert.deepEqual(receipts[1], receipts[0]);
    assert.equal(receipts[0].status, '0x1');
    return receipts[0];
  });
  const height = Number(BigInt(receipt.blockNumber));
  let evidenceCount = 0;
  for (let number = 1; number <= height; number++) {
    const blocks = await Promise.all([0, 1].map(i => rpc(i, 'eth_getBlockByNumber', ['0x' + number.toString(16), true])));
    assert.equal(blocks[1].hash, blocks[0].hash);
    assert.equal(blocks[1].stateRoot, blocks[0].stateRoot);
    evidenceCount += blocks[0].transactions.filter(tx => tx.shellType === 'timeoutEvidence').length;
    result.blocks.push({ height: number, hash: blocks[0].hash, stateRoot: blocks[0].stateRoot });
  }
  assert.equal(evidenceCount, 1, 'one genuine timeout certificate before the transfer');
  assert.ok(Date.now() - Date.parse(result.transaction.submittedAt) >= 10000, 'no shortened timeout');
  const tag = receipt.blockNumber;
  const before = await Promise.all([0, 1].map(i => offline(i, tag)));
  assert.deepEqual(before, [[1, 0, 0, 0], [1, 0, 0, 0]], 'only the absent assigned validator acquires one miss');
  for (const i of [0, 1]) {
    assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[1].address, tag])), BigInt(initial) + 1n);
    await until('finality', async () => Number(BigInt((await rpc(i, 'eth_getBlockByNumber', ['finalized', false])).number)) >= height);
  }
  result.receipt = receipt;
  result.phases.push({ phase: 'TCP certificate and transfer', height, evidenceCount, offline: before });
  await save();
  if (full) await fullLifecycle();
  await stop();
  await connect('restart');
  if (full) {
    const log = result.processes.find(p => p.phase === 'restart' && p.authority === keys[0].address).log;
    const bootnode = (await readFile(log, 'utf8')).match(/Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[A-Za-z0-9]+)/)?.[1];
    await start(2, 'restart-returned', bootnode);
    for (const i of [0, 1, 2]) {
      assert.equal((await rpc(i, 'eth_getBlockByNumber', [result.fullTip.receipt.blockNumber, false])).hash, result.fullTip.hash);
      assert.deepEqual(await offline(i), [0, 0, 0, 0]);
    }
  }
  for (const i of [0, 1]) {
    const block = await rpc(i, 'eth_getBlockByNumber', [tag, false]);
    const original = result.blocks.find(block => block.height === height);
    assert.equal(block.hash, original.hash);
    assert.equal(block.stateRoot, original.stateRoot);
    assert.deepEqual(await offline(i, tag), [1, 0, 0, 0]);
    assert.deepEqual(await rpc(i, 'eth_getTransactionReceipt', [hash]), receipt);
    assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[1].address, tag])), BigInt(initial) + 1n);
  }
  result.phases.push({ phase: full ? 'all three physical processes restarted' : 'both physical processes restarted', height, offline: [1, 0, 0, 0] });
  result.exitCode = 0;
} catch (error) {
  result.exitCode = 1;
  result.error = error.stack;
} finally {
  await stop();
  result.finishedAt = new Date().toISOString();
  await save();
  console.log(JSON.stringify({ exitCode: result.exitCode, result: join(directory, 'result.json'), error: result.error }));
  process.exitCode = result.exitCode;
}
