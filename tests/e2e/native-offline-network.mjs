#!/usr/bin/env node
// Real TCP/RocksDB acceptance for certified offline enforcement and restart.
// Requires Node 20+ and `cargo build -p shell-cli --features libp2p`.
// Run: node tests/e2e/native-offline-network.mjs
// Add --algorithm=slhdsa for the existing SLH-DSA-SHA2-256f fallback.
// Add --interrupt-work to crash/reopen a voter before quorum and recover its original work.
// Add --aa-work with --interrupt-work and SHELL_SDK_ENTRY for a two-call AA batch.
// Add --aa-revert to check rollback when its second inner call reverts.
// Add --reference-validator to deploy/install the key-bound ML-DSA reference policy first.
// Add --session-work for a real target/value/expiry-constrained ML-DSA session.
// Add --paymaster-work for genuine registered EOA gas sponsorship.
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
import { fileURLToPath, pathToFileURL } from 'node:url';

const full = process.argv.includes('--full');
const interruptWork = process.argv.includes('--interrupt-work');
const aaWork = process.argv.includes('--aa-work');
const aaRevert = process.argv.includes('--aa-revert');
const referenceValidator = process.argv.includes('--reference-validator');
const sessionWork = process.argv.includes('--session-work');
const paymasterWork = process.argv.includes('--paymaster-work');
const contractPaymasterWork = process.argv.includes('--contract-paymaster-work');
assert.ok(!contractPaymasterWork || (aaWork && !paymasterWork && !sessionWork && !referenceValidator), '--contract-paymaster-work requires --aa-work without other policy options');
assert.ok(!paymasterWork || (aaWork && !referenceValidator && !sessionWork), '--paymaster-work requires --aa-work without session/reference policy');
assert.ok(!sessionWork || (aaWork && !referenceValidator), '--session-work requires --aa-work without reference policy');
assert.ok(!referenceValidator || aaWork, '--reference-validator requires --aa-work');
assert.ok(!aaRevert || aaWork, '--aa-revert requires --aa-work');
const receivedValue = aaWork ? (aaRevert ? 0n : 3n) : 1n;
assert.ok(!aaWork || (interruptWork && !full), '--aa-work requires the short --interrupt-work mode');
assert.ok(!aaWork || process.env.SHELL_SDK_ENTRY, 'Set SHELL_SDK_ENTRY to a compatible V2 source SDK dist/index.js for --aa-work');
const algorithms = process.argv.slice(2).filter(arg => arg.startsWith('--algorithm='));
assert.ok(algorithms.length <= 1, 'Select one algorithm');
const algorithm = algorithms[0]?.slice('--algorithm='.length) ?? 'mldsa65';
assert.ok(!(paymasterWork || contractPaymasterWork) || algorithm === 'mldsa65', 'This EOA sponsored Work entry tests ML-DSA sender/paymaster');
assert.ok(!sessionWork || algorithm === 'mldsa65', 'This session Work entry tests ML-DSA root and session');
assert.ok(!referenceValidator || algorithm === 'mldsa65', 'The reference policy supports the ML-DSA family; select mldsa65');
assert.ok(['mldsa65', 'slhdsa'].includes(algorithm), 'Supported algorithms: mldsa65, slhdsa');
assert.ok(process.argv.slice(2).every(arg => arg === '--full' || arg === '--interrupt-work' || arg === '--aa-work' || arg === '--aa-revert' || arg === '--reference-validator' || arg === '--session-work' || arg === '--paymaster-work' || arg === '--contract-paymaster-work' || arg.startsWith('--algorithm=')), 'Supported options: --full, --interrupt-work, --aa-work, --aa-revert, --reference-validator, --session-work, --paymaster-work, --contract-paymaster-work, --algorithm=mldsa65|slhdsa');
const signatureType = algorithm === 'slhdsa' ? 'SphincsSha2256f' : 'MlDsa65';
const binary = resolve(process.env.NODE_BIN ?? fileURLToPath(new URL('../../target/debug/shell-node', import.meta.url)));
const directory = await mkdtemp(join(tmpdir(), 'shell-offline-network-'));
const result = { startedAt: new Date().toISOString(), directory, binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), processes: [], blocks: [], phases: [], scope: full ? '100 real assigned misses, native epoch suspension/recovery, TCP quorum, new peer catch-up and physical RocksDB restart.' : 'One real assigned miss, TCP weighted quorum, RocksDB import and physical restart; threshold remains 100 and is not exercised here.' };
const pause = ms => new Promise(done => setTimeout(done, ms));
result.algorithm = algorithm;
result.aaWork = aaWork;
result.aaRevert = aaRevert;
result.referenceValidator = referenceValidator;
result.sessionWork = sessionWork;
result.paymasterWork = paymasterWork;
result.contractPaymasterWork = contractPaymasterWork;
const initial = '0xd3c21bcecceda1000000';
let workBaseHeight = 0, senderStartNonce = 0, recipientStartBalance = BigInt(initial);
result.toolchain = { node: process.version, platform: process.platform, arch: process.arch };
const sdkEntry = aaWork ? pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)) : undefined;
const sdk = sdkEntry ? await import(sdkEntry.href) : undefined;
const unregisteredPaymaster = paymasterWork ? new sdk.ShellSigner('MlDsa65', sdk.MlDsa65Adapter.generate()) : undefined;
if (sdkEntry) result.sdkVersion = JSON.parse(await readFile(new URL('../package.json', sdkEntry), 'utf8')).version;
result.interruptWork = interruptWork;
result.certificates = [];
const save = () => writeFile(join(directory, 'result.json'), JSON.stringify(result, null, 2));
const password = join(directory, 'password.txt');
await writeFile(password, randomBytes(24).toString('hex'), { mode: 0o600 });
const keys = [];
for (let i = 0; i < 3; i++) {
  const path = join(directory, `validator-${i}.json`);
  const generated = spawnSync(binary, ['--password-file', password, 'key', 'generate', '--algorithm', algorithm, '--output', path], { encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const key = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(key.key_type, algorithm === 'slhdsa' ? 'sphincs-sha2-256f' : algorithm);
  keys.push({ path, address: key.address, publicKey: '0x' + key.public_key });
}
const genesis = { chain_id: 1337, chain_name: 'offline-network-acceptance', network_type: 'Dev', timestamp: Math.floor(Date.now() / 1000), gas_limit: 50000000, extra_data: 'offline-network-acceptance', alloc: Object.fromEntries(keys.map(key => [key.address, { balance: initial, nonce: 0, code: null, storage: null }])), boot_nodes: [], consensus: { engine: 'wpoa', authorities: keys.map(key => key.address), authority_pubkeys: keys.map(key => key.publicKey), weights: [1, 1, 3], stakes: [], block_time_secs: 2, max_future_secs: 300, epoch_length: 10 }, offline_enforcement: { activation_height: 1, epoch_length: 10, block_time_secs: 2, heartbeat_interval_secs: 600 } };
// Exercise the native AccountManager error path only in this new isolated mode.
if ((sessionWork || paymasterWork || contractPaymasterWork) && aaRevert) genesis.aa_account_manager_height = 0;
if (paymasterWork || contractPaymasterWork) genesis.fee_accounting_activation_height = 0;
if (paymasterWork) {
  genesis.fee_accounting_activation_height = 0;
  genesis.alloc[unregisteredPaymaster.getAddress()] = { balance: initial, nonce: 0, code: null, storage: null };
}
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
  // Session rejection snapshots add reads; retain the normal server rate limit.
  if (sessionWork || paymasterWork || contractPaymasterWork) await pause(100);
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
  const args = ['run', '--datadir', join(directory, `node-${authority}`), '--keystore', keys[authority].path, '--password-file', password, '--rpc-addr', `127.0.0.1:${ports[i]}`, '--metrics-addr', '127.0.0.1:0', '--network', 'dev', '--chain-id', '1337', '--consensus-engine', 'wpoa', '--block-time', '2000', '--max-idle-interval', '600', '--node-role', 'validator', '--db', 'rocksdb', '--storage-profile', 'full', '--rpc-api', referenceValidator || ((sessionWork || paymasterWork || contractPaymasterWork) && aaRevert) ? 'eth,net,web3,shell,debug' : 'eth,net,web3,shell', '--p2p', '--p2p-addr', '127.0.0.1:0', '--log-level', 'info'];
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
  const raw = await rpc(i, 'eth_getStorageAt', [registry, '0x' + BigInt(validatorSlot).toString(16), tag]);
  const padded = raw.slice(2).padStart(64, '0');
  return [0, 1, 2, 3].map(index => Number(BigInt('0x' + padded.slice(index * 16, (index + 1) * 16))));
}
async function send(i, nonce, to = keys[1].address, data) {
  if (aaWork) {
    assert.equal(data, undefined, 'this bounded AA crash case transfers only');
    const authority = [0, 2, 1][i];
    const signer = await sdk.decryptKeystore(JSON.parse(await readFile(keys[authority].path, 'utf8')), (await readFile(password, 'utf8')).trim());
    try {
      assert.equal(signer.getAddress(), keys[authority].address);
      const provider = sdk.createShellProvider({ rpcHttpUrl: urls[i] });
      const gasPrice = Number(BigInt(await rpc(i, 'eth_gasPrice')));
      if (sessionWork) return await sendSessionWork(i, signer, provider, nonce, to, gasPrice);
      if (paymasterWork) return await sendPaymasterWork(i, signer, provider, nonce, to, gasPrice);
      if (contractPaymasterWork) return await sendContractPaymasterWork(i, signer, provider, nonce, to, gasPrice);
      const { tx, aa_bundle } = sdk.buildBatchTransaction({ chainId: 1337, nonce, innerCalls: [sdk.buildInnerTransfer(to, 1n), aaRevert ? sdk.buildInnerCall(sdk.accountManagerAddress, '0xffffffff', 100000) : sdk.buildInnerTransfer(to, 2n)], gasLimit: 300000, maxFeePerGas: gasPrice * 2, maxPriorityFeePerGas: 0 });
      const signed = await signer.buildSignedTransaction({ tx, aaBundle: aa_bundle, includePublicKey: true });
      const hash = await provider.sendTransaction(signed);
      result.transaction = { hash, submittedAt: new Date().toISOString(), entry: 'SDK buildBatchTransaction/buildSignedTransaction/sendTransaction', innerValues: aaRevert ? ['1', '0'] : ['1', '2'], nonce };
      return hash;
    } finally { signer.dispose(); }
  }
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
async function sendSessionWork(i, root, provider, nonce, to, gasPrice) {
  const session = sdk.MlDsa65Adapter.generate();
  const other = sdk.MlDsa65Adapter.generate();
  const before = async () => ({
    nonce: await rpc(i, 'eth_getTransactionCount', [root.getAddress(), 'latest']),
    balance: await rpc(i, 'eth_getBalance', [root.getAddress(), 'latest']),
    recipient: await rpc(i, 'eth_getBalance', [to, 'latest']),
    rootKey: await rpc(i, 'shell_getPqPubkey', [root.getAddress()]),
  });
  const options = { chainId: 1337, nonce,
    innerCalls: [sdk.buildInnerTransfer(to, 1n), aaRevert ? sdk.buildInnerCall(sdk.accountManagerAddress, '0xffffffff', 100000) : sdk.buildInnerTransfer(to, 2n)],
    gasLimit: 300000, maxFeePerGas: gasPrice * 2, maxPriorityFeePerGas: 0 };
  const valueCap = aaRevert ? 1n : 3n;
  const target = aaRevert ? null : to;
  async function signed({ valueCap: cap = valueCap, target: allowedTarget = target, expiryBlock = 2,
    authorizer = root, sessionSigner = session } = {}) {
    const draft = sdk.buildBatchTransaction(options);
    const auth = await sdk.createSessionAuth(authorizer, session.getPublicKey(), 1,
      { chainId: 1337n, expiryBlock, valueCap: cap, target: allowedTarget });
    draft.aa_bundle.session_auth = auth;
    const hash = sdk.hashBatchTransaction(draft.tx, draft.aa_bundle, 'MlDsa65');
    const final = await sdk.finalizeSessionAuth(auth, sessionSigner, hash);
    const batch = sdk.buildSessionKeyTransaction({ ...options, sessionAuth: final });
    return sdk.buildSignedTransaction({ from: root.getAddress(), tx: batch.tx,
      signatureType: 'MlDsa65', signature: final.session_signature,
      senderPubkey: root.getPublicKey(), aaBundle: batch.aa_bundle });
  }
  result.session = { root: root.getAddress(), publicKey: '0x' + Buffer.from(session.getPublicKey()).toString('hex'),
    target, valueCap: valueCap.toString(), exclusiveExpiry: 2, beforeWork: await before(), rejectionControls: [] };
  try {
    for (const [label, constraints, expected] of [
      ['value cap', { valueCap: valueCap - 1n }, /session.*value cap/i],
      ['target', { target: aaRevert ? to : keys[0].address }, /session.*target mismatch/i],
      ['exclusive expiry', { expiryBlock: 1 }, /session.*expired/i],
      ['root identity', { authorizer: other }, /session.*root authorization signature invalid/i],
      ['session identity', { sessionSigner: other }, /session.*tx signature invalid/i],
    ]) {
      const state = await before();
      const packet = await signed(constraints);
      let error;
      try { await provider.sendTransaction(packet); }
      catch (e) { error = String(e); }
      assert.match(error ?? '', expected, label);
      assert.deepEqual(await before(), state, label + ': no account mutation');
      result.session.rejectionControls.push({ label, error, stateUnchanged: true });
      await save();
    }
    const packet = await signed();
    const hash = await provider.sendTransaction(packet);
    result.transaction = { hash, submittedAt: new Date().toISOString(),
      entry: 'SDK genuine root/session authorization and V2 session batch', nonce, innerValues: aaRevert ? ['1', '0'] : ['1', '2'] };
    return hash;
  } finally { session.dispose(); other.dispose(); }
}
async function sendPaymasterWork(i, root, provider, nonce, to, gasPrice) {
  const passwordText = (await readFile(password, 'utf8')).trim();
  const payer = await sdk.decryptKeystore(JSON.parse(await readFile(keys[0].path, 'utf8')), passwordText);
  const other = await sdk.decryptKeystore(JSON.parse(await readFile(keys[1].path, 'utf8')), passwordText);
  const options = { chainId: 1337, nonce,
    innerCalls: [sdk.buildInnerTransfer(to, 1n), aaRevert ? sdk.buildInnerCall(sdk.accountManagerAddress, '0xffffffff', 100000) : sdk.buildInnerTransfer(to, 2n)],
    gasLimit: 300000, maxFeePerGas: gasPrice * 2, maxPriorityFeePerGas: 0 };
  const snapshot = async () => {
    const state = {};
    for (const address of [root.getAddress(), payer.getAddress(), to, unregisteredPaymaster.getAddress()]) {
      state[address] = {
        nonce: await rpc(i, 'eth_getTransactionCount', [address, 'latest']),
        balance: await rpc(i, 'eth_getBalance', [address, 'latest']),
        key: await rpc(i, 'shell_getPqPubkey', [address]),
      };
    }
    return state;
  };
  async function signed({ targetPayer = payer, authorizer = targetPayer, boundSender = root.getAddress() } = {}) {
    const draft = sdk.buildBatchTransaction(options);
    draft.aa_bundle.paymaster = targetPayer.getAddress();
    const signature = await authorizer.sign(sdk.hashPaymasterTransaction(boundSender, draft.tx, draft.aa_bundle, 'MlDsa65'));
    const batch = sdk.buildSponsoredTransaction({ ...options, paymaster: targetPayer.getAddress(), paymasterSignature: signature });
    return root.buildSignedTransaction({ tx: batch.tx, aaBundle: batch.aa_bundle, includePublicKey: true });
  }
  result.paymaster = { sender: root.getAddress(), payer: payer.getAddress(), unregistered: unregisteredPaymaster.getAddress(),
    beforeWork: await snapshot(), rejectionControls: [] };
  try {
    assert.equal(result.paymaster.beforeWork[payer.getAddress()].key, keys[0].publicKey, 'real genesis authority key is registered');
    assert.equal(result.paymaster.beforeWork[unregisteredPaymaster.getAddress()].key, null);
    for (const [label, constraints, expected] of [
      ['missing registered payer key', { targetPayer: unregisteredPaymaster }, /paymaster pubkey not found/i],
      ['payer signing identity', { authorizer: other }, /paymaster signature invalid/i],
      ['sender binding', { boundSender: other.getAddress() }, /paymaster signature invalid/i],
      ['batch binding', {}, /paymaster signature invalid/i],
    ]) {
      const before = await snapshot();
      let packet = await signed(constraints);
      if (label === 'batch binding') {
        packet = structuredClone(packet);
        packet.tx.value = '0x4';
        packet.aa_bundle.inner_calls[1].value = '0x3';
        packet = await root.buildSignedTransaction({ tx: packet.tx, aaBundle: packet.aa_bundle, includePublicKey: true });
      }
      let error;
      try { await provider.sendTransaction(packet); } catch (e) { error = String(e); }
      assert.match(error ?? '', expected, label);
      assert.deepEqual(await snapshot(), before, label + ': no account mutation');
      result.paymaster.rejectionControls.push({ label, error, stateUnchanged: true });
      await save();
    }
    const packet = await signed();
    assert.deepEqual(packet.aa_bundle.inner_calls.map(call => BigInt(call.value)), aaRevert ? [1n, 0n] : [1n, 2n], 'positive input retains the promised batch');
    assert.equal(BigInt(packet.tx.value), aaRevert ? 1n : 3n);
    const hash = await provider.sendTransaction(packet);
    result.transaction = { hash, submittedAt: new Date().toISOString(), nonce, innerValues: aaRevert ? ['1', '0'] : ['1', '2'],
      entry: 'SDK genuine EOA paymaster sender/batch-bound sponsorship' };
    return hash;
  } finally { payer.dispose(); other.dispose(); unregisteredPaymaster.dispose(); }
}
async function sendContractPaymasterWork(i, root, provider, nonce, to, gasPrice) {
  const other = await sdk.decryptKeystore(JSON.parse(await readFile(keys[1].path, 'utf8')),
    (await readFile(password, 'utf8')).trim());
  const payer = result.contractPrefix.contract;
  const context = Buffer.from(result.contractPrefix.context.slice(2), 'hex');
  const snapshot = async () => {
    const state = {};
    for (const address of [root.getAddress(), other.getAddress(), payer]) {
      state[address] = {
        nonce: await rpc(i, 'eth_getTransactionCount', [address, 'latest']),
        balance: await rpc(i, 'eth_getBalance', [address, 'latest']),
        key: await rpc(i, 'shell_getPqPubkey', [address]),
        code: await rpc(i, 'eth_getCode', [address, 'latest']),
      };
    }
    return state;
  };
  async function signed(signer = root, payerContext = context, price = gasPrice * 2) {
    const batch = sdk.buildContractPaymasterTransaction({ chainId: 1337,
      nonce: signer === root ? nonce : 0,
      innerCalls: [sdk.buildInnerTransfer(to, 1n), aaRevert ? sdk.buildInnerCall(sdk.accountManagerAddress, '0xffffffff', 100000) : sdk.buildInnerTransfer(to, 2n)],
      gasLimit: 300000, maxFeePerGas: price, maxPriorityFeePerGas: 0,
      paymaster: payer, paymasterContext: payerContext });
    assert.equal(batch.aa_bundle.paymaster_signature, null, 'contract policy uses context, not an EOA signature');
    return signer.buildSignedTransaction({ tx: batch.tx, aaBundle: batch.aa_bundle, includePublicKey: true });
  }
  result.paymaster = { sender: root.getAddress(), payer, beforeWork: await snapshot(), rejectionControls: [] };
  try {
    assert.equal(result.paymaster.beforeWork[payer].code, result.contractPrefix.code);
    const changedContext = Buffer.from(context);
    changedContext[0] ^= 1;
    for (const [label, signer, candidateContext, price] of [
      ['different authenticated sender', other, context, gasPrice * 2],
      ['changed context word', root, changedContext, gasPrice * 2],
      ['short context', root, context.subarray(0, 31), gasPrice * 2],
      ['maximum sponsorship cost above policy cap', root, context, 1000000000000000],
    ]) {
      const before = await snapshot();
      const packet = await signed(signer, candidateContext, price);
      let error;
      try { await provider.sendTransaction(packet); } catch (e) { error = String(e); }
      assert.match(error ?? '', /contract paymaster rejected/i, label);
      assert.deepEqual(await snapshot(), before, label + ': no account mutation');
      result.paymaster.rejectionControls.push({ label, error, stateUnchanged: true });
      await save();
    }
    const packet = await signed();
    assert.deepEqual(packet.aa_bundle.inner_calls.map(call => BigInt(call.value)), aaRevert ? [1n, 0n] : [1n, 2n]);
    assert.equal(BigInt(packet.tx.value), aaRevert ? 1n : 3n);
    const hash = await provider.sendTransaction(packet);
    result.transaction = { hash, submittedAt: new Date().toISOString(), nonce, innerValues: aaRevert ? ['1', '0'] : ['1', '2'],
      entry: 'SDK buildContractPaymasterTransaction with real conditional on-chain policy' };
    return hash;
  } finally { other.dispose(); }
}
async function checkSponsoredState(i, receipt, hash) {
  const fee = BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice);
  assert.ok(fee > 0n);
  const { sender, payer, beforeWork } = result.paymaster;
  assert.equal(BigInt(await rpc(i, 'eth_getBalance', [payer, receipt.blockNumber])), BigInt(beforeWork[payer].balance) - fee, 'payer pays exactly actual gas fee');
  assert.equal(await rpc(i, 'eth_getTransactionCount', [payer, receipt.blockNumber]), beforeWork[payer].nonce, 'sponsorship consumes no payer nonce');
  const block = await rpc(i, 'eth_getBlockByNumber', [receipt.blockNumber, false]);
  assert.equal(block.miner, sender, 'the restored weighted view assigns C as proposer');
  // Shell pays the full billed fee once through its deterministic gas reward.
  assert.equal(BigInt(await rpc(i, 'eth_getBalance', [sender, receipt.blockNumber])), BigInt(beforeWork[sender].balance) + fee - receivedValue, 'sender funds only committed value and earns its proposer reward');
  assert.equal(await rpc(i, 'shell_getPqPubkey', [sender]), keys[2].publicKey);
  assert.equal(await rpc(i, 'shell_getPqPubkey', [payer]), contractPaymasterWork ? null : keys[0].publicKey);
  if (contractPaymasterWork) assert.equal(await rpc(i, 'eth_getCode', [payer, receipt.blockNumber]), result.contractPrefix.code);
  const sponsored = await rpc(i, 'shell_isSponsored', [hash]);
  assert.equal(sponsored.sponsored, true);
  assert.equal(sponsored.sender, sender);
  assert.equal(sponsored.paymaster, payer);
  assert.equal(sponsored.inner_call_count, 2);
  result.paymaster.fee = '0x' + fee.toString(16);
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
async function evidenceViews(i, block) {
  for (const tx of block.transactions.filter(tx => tx.shellType === 'timeoutEvidence')) {
    const proof = JSON.parse(Buffer.from(tx.input.slice(2), 'hex').toString('utf8'));
    if (aaWork) {
      assert.equal(proof.opportunity.Work.transaction.tx.tx_type, 126);
      assert.equal(proof.opportunity.Work.transaction.aa_bundle.inner_calls.length, 2);
      if (sessionWork) assert.equal(proof.opportunity.Work.transaction.aa_bundle.session_auth.session_pubkey, result.session.publicKey);
      if (paymasterWork || contractPaymasterWork) assert.equal(proof.opportunity.Work.transaction.aa_bundle.paymaster, result.paymaster.payer);
    }
    assert.equal(proof.context.proposer, keys[1].address);
    if (interruptWork) assert.deepEqual(proof.opportunity.Work.transaction, result.pendingVote.opportunity.Work.transaction, 'the original signed work, without resubmission');
    assert.deepEqual(proof.signers.map(signer => signer.address).sort(), [keys[0].address, keys[2].address].sort());
    for (const signer of proof.signers) {
      assert.equal(signer.signature.sig_type, signatureType);
      const key = keys.find(key => key.address === signer.address);
      assert.equal('0x' + Buffer.from(signer.public_key).toString('hex'), key.publicKey);
      if (algorithm === 'slhdsa') assert.equal(signer.signature.data.length, 49856);
    }
    result.certificates.push({ peer: i, hash: tx.hash, algorithm, signatures: proof.signers.map(signer => ({ address: signer.address, bytes: signer.signature.data.length })), payloadBytes: (tx.input.length - 2) / 2 });
    const receipts = await rpc(i, 'eth_getBlockReceipts', [block.number]);
    const single = await rpc(i, 'eth_getTransactionReceipt', [tx.hash]);
    const summary = await rpc(i, 'shell_getTransactionSummary', [tx.hash, { includeReceipt: true }]);
    for (const view of [tx, receipts.find(receipt => receipt.transactionHash === tx.hash), single, summary.transaction, summary.receipt]) {
      assert.ok(view, 'evidence remains queryable');
      assert.equal(view.type, '0x82');
      assert.equal(view.shellType, 'timeoutEvidence');
      assert.equal(view.rewardKind ?? null, null, 'consensus evidence is not a reward');
      assert.equal(view.rewardSourceHash ?? null, null);
    }
  }
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
async function contractPaymasterPrefix() {
  const bootnode = await start(0, 'contract-prefix');
  await start(1, 'contract-prefix', bootnode);
  await start(2, 'contract-prefix', bootnode);
  await until('all contract prefix peers connected', async () =>
    (await Promise.all([0, 1, 2].map(i => rpc(i, 'net_peerCount')))).every(n => BigInt(n) >= 1n));
  const signer = await sdk.decryptKeystore(JSON.parse(await readFile(keys[2].path, 'utf8')),
    (await readFile(password, 'utf8')).trim());
  const provider = sdk.createShellProvider({ rpcHttpUrl: urls[1] });
  const context = randomBytes(32).toString('hex');
  const costCap = 1000000000000000000n;
  // Retained validatePaymasterOp(address,bytes,uint256,bytes) ABI: sender at4,
  // maximum cost at68, dynamic context offset at100. The address argument maps
  // the last20 bytes; this fixture makes no full32-byte ABI identity claim.
  // Return senderMatch AND costWithinCap AND contextLength32 AND contextMatch.
  const code = '6004357f' + keys[2].address.slice(-40).padStart(64, '0') + '14'
    + '7f' + costCap.toString(16).padStart(64, '0') + '604435111516'
    + '606435600401803560201490602001357f' + context + '14161660005260206000f3';
  const size = (code.length / 2).toString(16).padStart(4, '0');
  const creation = '0x61' + size + '61000f60003961' + size + '6000f3' + code;
  result.contractPrefix = { context: '0x' + context, costCap: costCap.toString(), code: '0x' + code, transactions: [] };
  async function direct(label, nonce, to, data, value = 0n) {
    const tx = sdk.buildTransaction({ chainId: 1337, nonce, to, data, value, gasLimit: 3000000 });
    const hash = await provider.sendTransaction(await signer.buildSignedTransaction({ tx, includePublicKey: true }));
    const receipt = await until(label, async () => {
      const receipts = await Promise.all([0, 1, 2].map(i => rpc(i, 'eth_getTransactionReceipt', [hash])));
      if (!receipts.every(Boolean)) return false;
      for (const other of receipts.slice(1)) assert.deepEqual(other, receipts[0]);
      assert.equal(receipts[0].status, '0x1', label);
      return receipts[0];
    });
    result.contractPrefix.transactions.push({ label, hash, receipt });
    await save();
    return receipt;
  }
  try {
    const deployed = await direct('deploy and fund conditional contract paymaster', 0, null, creation, 1000000000000000000000n);
    result.contractPrefix.contract = deployed.contractAddress;
    for (const i of [0, 1, 2]) {
      assert.equal(await rpc(i, 'eth_getCode', [deployed.contractAddress, 'latest']), '0x' + code);
      assert.equal(BigInt(await rpc(i, 'eth_getBalance', [deployed.contractAddress, 'latest'])), 1000000000000000000000n);
    }
    // Five genuine transactions, not member count3, complete weights1+1+3.
    for (let nonce = 1; nonce < 5; nonce++) await direct('complete weighted prefix cycle ' + nonce, nonce, keys[2].address, '0x');
    workBaseHeight = Number(BigInt(await rpc(1, 'eth_blockNumber')));
    assert.equal(workBaseHeight, 5);
    senderStartNonce = Number(BigInt(await rpc(1, 'eth_getTransactionCount', [keys[2].address, 'latest'])));
    assert.equal(senderStartNonce, 5);
    recipientStartBalance = BigInt(await rpc(1, 'eth_getBalance', [keys[1].address, 'latest']));
    const raw = Buffer.concat([Buffer.from('shell:offline-state:v1:validator:'), Buffer.from(keys[1].address.slice(2), 'hex')]);
    validatorSlot = await rpc(1, 'web3_sha3', ['0x' + raw.toString('hex')]);
    const tip = await rpc(1, 'eth_getBlockByNumber', ['latest', false]);
    for (const i of [0, 1, 2]) {
      await until('contract prefix finalized on every peer', async () =>
        Number(BigInt((await rpc(i, 'eth_getBlockByNumber', ['finalized', false])).number)) === workBaseHeight);
      assert.equal((await rpc(i, 'eth_getBlockByNumber', ['latest', false])).hash, tip.hash);
      assert.deepEqual(await offline(i), [0, 0, 0, 0]);
    }
    Object.assign(result.contractPrefix, { baseHeight: workBaseHeight, baseHash: tip.hash,
      nextWorkNonce: senderStartNonce, recipientStartBalance: '0x' + recipientStartBalance.toString(16) });
    await save();
  } finally { signer.dispose(); await stop(); }
}
async function referencePrefix() {
  const bootnode = await start(0, 'reference-prefix');
  await start(1, 'reference-prefix', bootnode);
  await start(2, 'reference-prefix', bootnode);
  await until('all prefix peers connected', async () =>
    (await Promise.all([0, 1, 2].map(i => rpc(i, 'net_peerCount')))).every(n => BigInt(n) >= 1n));
  const signer = await sdk.decryptKeystore(JSON.parse(await readFile(keys[2].path, 'utf8')),
    (await readFile(password, 'utf8')).trim());
  const provider = sdk.createShellProvider({ rpcHttpUrl: urls[1] });
  const { createRequire } = await import('node:module');
  const sdkRequire = createRequire(sdkEntry);
  const { blake3 } = await import(pathToFileURL(sdkRequire.resolve('@noble/hashes/blake3')).href);
  const { keccak_256 } = await import(pathToFileURL(sdkRequire.resolve('@noble/hashes/sha3')).href);
  const hex = bytes => Buffer.from(bytes).toString('hex');
  const snapshot = async () => ({
    nonce: await rpc(1, 'eth_getTransactionCount', [keys[2].address, 'latest']),
    owner: await rpc(1, 'eth_getBalance', [keys[2].address, 'latest']),
    recipient: await rpc(1, 'eth_getBalance', [keys[1].address, 'latest']),
    publicKey: await rpc(1, 'shell_getPqPubkey', [keys[2].address]),
  });
  async function direct(label, nonce, to, data, value = 0n, includePublicKey = true) {
    const tx = sdk.buildTransaction({ chainId: 1337, nonce, to, data, value, gasLimit: 3000000 });
    const hash = await provider.sendTransaction(await signer.buildSignedTransaction({ tx, includePublicKey }));
    const receipt = await until(label, async () => {
      const receipts = await Promise.all([0, 1, 2].map(i => rpc(i, 'eth_getTransactionReceipt', [hash])));
      if (!receipts.every(Boolean)) return false;
      for (const other of receipts.slice(1)) assert.deepEqual(other, receipts[0]);
      assert.equal(receipts[0].status, '0x1', label);
      return receipts[0];
    });
    result.referencePrefix.transactions.push({ label, hash, receipt });
    await save();
    return receipt;
  }
  result.referencePrefix = { transactions: [] };
  try {
    const creation = (await readFile(new URL('../../contracts/DefaultPQValidator.bin', import.meta.url), 'utf8')).trim();
    const deployed = await direct('deploy real key-bound reference policy', 0, null,
      '0x' + creation + hex(blake3(signer.getPublicKey())));
    const code = await rpc(1, 'eth_getCode', [deployed.contractAddress, 'latest']);
    assert.ok(code.length > 2);
    const policyHash = '0x' + hex(keccak_256(Buffer.from(code.slice(2), 'hex')));
    await direct('install deployed reference policy', 1, sdk.accountManagerAddress,
      sdk.encodeSetValidationCodeCalldata(policyHash));
    await direct('real reference owner success', 2, keys[1].address, '0x', 11n);
    // A full weight cycle (1+1+3), not the three-member count, keeps the next
    // weighted slot assigned to absent B. Use real owner-authorized transfers.
    const recipientBefore = BigInt(await rpc(1, 'eth_getBalance', [keys[1].address, 'latest']));
    await direct('registered-key-reference policy control', 3, keys[1].address, '0x', 1n, false);
    await direct('embedded-key policy control', 4, keys[1].address, '0x', 2n);
    assert.equal(BigInt(await rpc(1, 'eth_getBalance', [keys[1].address, 'latest'])) - recipientBefore, 3n);

    const before = await snapshot();
    const attacker = new sdk.ShellSigner('MlDsa65', sdk.MlDsa65Adapter.generate(), keys[2].address);
    let error;
    try {
      const tx = sdk.buildTransaction({ chainId: 1337, nonce: 5, to: keys[1].address,
        value: 7n, data: '0x', gasLimit: 3000000 });
      try { await provider.sendTransaction(await attacker.buildSignedTransaction({ tx, includePublicKey: true })); }
      catch (e) { error = String(e); }
    } finally { attacker.dispose(); }
    assert.match(error ?? '', /validation contract rejected/i);
    assert.deepEqual(await snapshot(), before, 'unrelated true signer changes no account state');
    workBaseHeight = Number(BigInt(await rpc(1, 'eth_blockNumber')));
    assert.equal(workBaseHeight, 5, 'one full weighted cycle; five actual signed prefix transactions');
    senderStartNonce = Number(BigInt(before.nonce));
    assert.equal(senderStartNonce, 5);
    recipientStartBalance = BigInt(before.recipient);
    const raw = Buffer.concat([Buffer.from('shell:offline-state:v1:validator:'), Buffer.from(keys[1].address.slice(2), 'hex')]);
    validatorSlot = await rpc(1, 'web3_sha3', ['0x' + raw.toString('hex')]);
    const tip = await rpc(1, 'eth_getBlockByNumber', ['latest', false]);
    for (const i of [0, 1, 2]) {
      await until('prefix finalized on every peer', async () =>
        Number(BigInt((await rpc(i, 'eth_getBlockByNumber', ['finalized', false])).number)) === workBaseHeight);
      assert.equal((await rpc(i, 'eth_getBlockByNumber', ['latest', false])).hash, tip.hash);
      assert.deepEqual(await offline(i), [0, 0, 0, 0]);
    }
    Object.assign(result.referencePrefix, { contract: deployed.contractAddress, code, policyHash,
      wrongKeyError: error, beforeWork: before, baseHeight: workBaseHeight, baseHash: tip.hash,
      nextWorkNonce: senderStartNonce, recipientStartBalance: before.recipient });
    await save();
  } finally { signer.dispose(); await stop(); }
}
async function exportPending(label) {
  const output = join(directory, `${label}.jsonl`);
  const argv = ['--datadir', join(directory, 'node-2'), 'export-state', '--output', output];
  const exported = spawnSync(binary, argv, { encoding: 'utf8' });
  result.exports ??= [];
  result.exports.push({ argv, exitCode: exported.status, stdout: exported.stdout, stderr: exported.stderr });
  assert.equal(exported.status, 0, exported.stderr);
  const entries = (await readFile(output, 'utf8')).trim().split('\n').filter(line => !line.startsWith('META:')).map(line => JSON.parse(line));
  const votes = entries.filter(row => Buffer.from(row.key, 'base64').subarray(0, 4).toString() === 'TCV2').map(row => JSON.parse(Buffer.from(row.value, 'base64').toString()));
  const certificates = entries.filter(row => Buffer.from(row.key, 'base64').subarray(0, 4).toString() === 'TCC2');
  assert.equal(votes.length, 1, 'one actually durable pre-quorum vote');
  assert.equal(certificates.length, 0, 'C3 alone cannot certify the total weight5');
  assert.equal(votes[0].vote.validator, keys[2].address);
  assert.equal(votes[0].vote.context.proposer, keys[1].address);
  assert.equal(votes[0].vote.context.block_number, workBaseHeight + 1);
  assert.equal(votes[0].vote.context.view, 0);
  result.pendingVote = votes[0];
  await save();
}
async function inflightStart() {
  await start(1, 'pending-before-crash');
  const raw = Buffer.concat([Buffer.from('shell:offline-state:v1:validator:'), Buffer.from(keys[1].address.slice(2), 'hex')]);
  validatorSlot = await rpc(1, 'web3_sha3', ['0x' + raw.toString('hex')]);
  result.pendingTransferHash = await send(1, senderStartNonce);
  await save();
  for (let n = 0; n < 20; n++) {
    assert.equal(Number(BigInt(await rpc(1, 'eth_blockNumber'))), workBaseHeight, 'minority cannot produce a certified miss');
    if (aaWork) assert.equal(BigInt(await rpc(1, 'eth_getBalance', [keys[1].address, 'latest'])), recipientStartBalance, 'partial vote cannot execute either inner call');
    assert.deepEqual(await offline(1), [0, 0, 0, 0]);
    await pause(1000);
  }
  const child = children[1];
  assert.ok(child.kill('SIGKILL'));
  await new Promise(done => child.once('exit', done));
  const record = result.processes.find(record => record.pid === child.pid);
  Object.assign(record, { stoppedAt: new Date().toISOString(), exitCode: child.exitCode, signal: child.signalCode, expectedCrash: true });
  assert.equal(record.signal, 'SIGKILL');
  children.length = 0;
  await exportPending('pending-after-crash');
  const bootnode = await start(1, 'pending-reopened');
  assert.equal(await rpc(1, 'eth_getTransactionByHash', [result.pendingTransferHash]), null, 'volatile mempool is gone, original work is only in durable witness');
  for (let n = 0; n < 12; n++) {
    assert.equal(Number(BigInt(await rpc(1, 'eth_blockNumber'))), workBaseHeight);
    assert.deepEqual(await offline(1), [0, 0, 0, 0]);
    await pause(1000);
  }
  await start(0, 'quorum-peer-joined', bootnode);
  await until('peer reconnect', async () => BigInt(await rpc(0, 'net_peerCount')) > 0n && BigInt(await rpc(1, 'net_peerCount')) > 0n);
  result.phases.push({ phase: 'durable minority vote survives SIGKILL/reopen; genuine second signer joined without resubmitting original transfer' });
  await save();
}
try {
  if (referenceValidator) await referencePrefix();
  if (contractPaymasterWork) await contractPaymasterPrefix();
  if (interruptWork) await inflightStart();
  else await connect('initial');
  // Standard hashing RPC only derives the published native storage key; the
  // expected counter comes from the assigned-miss rule, not a runtime helper.
  const keyBytes = Buffer.concat([Buffer.from('shell:offline-state:v1:validator:'), Buffer.from(keys[1].address.slice(2), 'hex')]);
  validatorSlot = await rpc(0, 'web3_sha3', ['0x' + keyBytes.toString('hex')]);
  assert.deepEqual(await offline(0), [0, 0, 0, 0]);
  result.initialValidator = await rpc(0, 'shell_getValidatorStatus', [keys[1].address]);
  assert.equal(result.initialValidator.weight, 1);
  const hash = interruptWork ? result.pendingTransferHash : await send(1, 0);
  await save();
  const receipt = await until('transfer confirmation on both peers', async () => {
    const receipts = await Promise.all([0, 1].map(i => rpc(i, 'eth_getTransactionReceipt', [hash])));
    if (!receipts.every(Boolean)) return false;
    assert.deepEqual(receipts[1], receipts[0]);
    assert.equal(receipts[0].status, aaRevert ? '0x0' : '0x1');
    return receipts[0];
  });
  const height = Number(BigInt(receipt.blockNumber));
  if ((sessionWork || paymasterWork || contractPaymasterWork) && aaRevert) {
    const traces = await Promise.all([0, 1].map(i => rpc(i, 'debug_traceTransaction', [hash])));
    assert.deepEqual(traces[1], traces[0], 'independent native failure replay');
    assert.equal(traces[0].failed, true);
    assert.match(Buffer.from(traces[0].output.slice(2), 'hex').toString(), /unknown function selector/i);
    const authorization = sessionWork ? result.session : result.paymaster;
    authorization.nativeFailureTrace = traces[0];
    authorization.accountManagerActivationHeight = 0;
  }
  if (aaRevert) assert.ok(BigInt(receipt.gasUsed) > 0n, 'reverting outer transaction still consumes gas');
  if (aaWork) for (const i of [0, 1]) {
    assert.equal((await rpc(i, 'eth_getTransactionByHash', [hash])).type, '0x7e');
    assert.equal(BigInt(await rpc(i, 'eth_getTransactionCount', [keys[2].address, receipt.blockNumber])), BigInt(senderStartNonce + 1), 'one nonce for two inner calls');
  }
  let evidenceCount = 0;
  for (let number = workBaseHeight + 1; number <= height; number++) {
    const blocks = await Promise.all([0, 1].map(i => rpc(i, 'eth_getBlockByNumber', ['0x' + number.toString(16), true])));
    assert.equal(blocks[1].hash, blocks[0].hash);
    assert.equal(blocks[1].stateRoot, blocks[0].stateRoot);
    for (const i of [0, 1]) await evidenceViews(i, blocks[i]);
    evidenceCount += blocks[0].transactions.filter(tx => tx.shellType === 'timeoutEvidence').length;
    result.blocks.push({ height: number, hash: blocks[0].hash, stateRoot: blocks[0].stateRoot });
  }
  assert.equal(evidenceCount, 1, 'one genuine timeout certificate before the transfer');
  assert.ok(Date.now() - Date.parse(result.transaction.submittedAt) >= 10000, 'no shortened timeout');
  const tag = receipt.blockNumber;
  if (paymasterWork || contractPaymasterWork) for (const i of [0, 1]) await checkSponsoredState(i, receipt, hash);
  const before = await Promise.all([0, 1].map(i => offline(i, tag)));
  assert.deepEqual(before, [[1, 0, 0, 0], [1, 0, 0, 0]], 'only the absent assigned validator acquires one miss');
  for (const i of [0, 1]) {
    assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[1].address, tag])), recipientStartBalance + receivedValue);
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
    const block = await rpc(i, 'eth_getBlockByNumber', [tag, true]);
    await evidenceViews(i, block);
    const original = result.blocks.find(block => block.height === height);
    assert.equal(block.hash, original.hash);
    assert.equal(block.stateRoot, original.stateRoot);
    assert.deepEqual(await offline(i, tag), [1, 0, 0, 0]);
    assert.deepEqual(await rpc(i, 'eth_getTransactionReceipt', [hash]), receipt);
    if (aaWork) assert.equal(BigInt(await rpc(i, 'eth_getTransactionCount', [keys[2].address, tag])), BigInt(senderStartNonce + 1));
    if (sessionWork) assert.equal(await rpc(i, 'shell_getPqPubkey', [keys[2].address]), keys[2].publicKey, 'session does not replace persisted root key');
    if ((sessionWork || paymasterWork || contractPaymasterWork) && aaRevert) assert.deepEqual(await rpc(i, 'debug_traceTransaction', [hash]), (sessionWork ? result.session : result.paymaster).nativeFailureTrace, 'native failed AA history after reopen');
    if (paymasterWork || contractPaymasterWork) await checkSponsoredState(i, receipt, hash);
    assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[1].address, tag])), recipientStartBalance + receivedValue);
  }
  result.phases.push({ phase: full ? 'all three physical processes restarted' : 'both physical processes restarted', height, offline: [1, 0, 0, 0] });
  result.exitCode = 0;
} catch (error) {
  result.exitCode = 1;
  result.error = error.stack;
} finally {
  await stop();
  unregisteredPaymaster?.dispose();
  result.finishedAt = new Date().toISOString();
  await save();
  console.log(JSON.stringify({ exitCode: result.exitCode, result: join(directory, 'result.json'), error: result.error }));
  process.exitCode = result.exitCode;
}
