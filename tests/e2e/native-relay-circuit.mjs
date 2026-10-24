// Manual acceptance for unreleased native circuit-relay support.
// Requires a RocksDB/libp2p shell-node and installed shell-sdk@0.14.0-rc.3.
// NODE_BIN=/path/to/shell-node SHELL_SDK_ENTRY=/path/to/shell-sdk/dist/index.js \
//   node tests/e2e/native-relay-circuit.mjs
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openSync, closeSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

assert.ok(process.env.NODE_BIN && process.env.SHELL_SDK_ENTRY, 'Set NODE_BIN and SHELL_SDK_ENTRY');
const binary = resolve(process.env.NODE_BIN);
const sdk = await import(pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)));
const directory = await mkdtemp(join(tmpdir(), 'shell-relay-circuit-'));
const report = { startedAt: new Date().toISOString(), nodes: [], opens: [], rpc: [], transactions: [] };
const signers = [];
const children = new Map();
const pause = ms => new Promise(done => setTimeout(done, ms));
const save = () => writeFile(join(directory, 'report.json'), JSON.stringify(report, null, 2));
const ports = new Set();
let requestId = 0;
let receiverCircuit;
const stripAnsi = text => text.replace(/\x1b\[[0-9;]*m/g, '');
async function freePort() {
  const server = createServer();
  await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
  const port = server.address().port;
  await new Promise(done => server.close(done));
  if (ports.has(port)) return freePort();
  ports.add(port); return port;
}
async function rpc(index, method, params = []) {
  await pause(50);
  const input = { jsonrpc: '2.0', id: ++requestId, method, params };
  const output = await (await fetch(`http://127.0.0.1:${report.nodes[index].rpc}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input), signal: AbortSignal.timeout(10000),
  })).json();
  report.rpc.push({ index, input, output });
  assert.equal(output.error, undefined, JSON.stringify(output.error));
  return output.result;
}
async function until(check, label) {
  for (let attempt = 0; attempt < 150; attempt++) {
    const value = await check(); if (value) return value;
    await pause(200);
  }
  throw Error(`Timed out: ${label}`);
}
function launch(index, args, reopen) {
  const node = report.nodes[index];
  node.log = join(node.directory, reopen ? 'reopen.log' : 'node.log');
  const fd = openSync(node.log, 'wx');
  const child = spawn(binary, args, {
    env: { ...process.env, RUST_LOG: 'info,shell_network=debug' }, stdio: ['ignore', fd, fd],
  });
  closeSync(fd);
  const opened = { index, log: node.log, pid: child.pid, argv: [binary, ...args], startedAt: new Date().toISOString() };
  report.opens.push(opened); children.set(index, { child, opened });
  child.once('error', error => { opened.spawnError = error.message; });
  return child;
}
async function start(index, reopen = false) {
  const node = report.nodes[index];
  if (reopen) { node.rpc = index ? await freePort() : null; node.p2p = await freePort(); }
  if (index === 0) {
    const child = launch(index, ['relay', '--datadir', node.directory,
      '--listen-addr', `127.0.0.1:${node.p2p}`,
      '--external-addr', `/ip4/127.0.0.1/tcp/${node.p2p}`], reopen);
    const info = await until(async () => {
      assert.equal(child.exitCode, null, 'Standalone relay exited before listening');
      for (const line of stripAnsi(await readFile(node.log, 'utf8')).split('\n')) {
        try { const value = JSON.parse(line); if (value.peer_id && value.listen_addresses) return value; }
        catch { /* Tracing lines are not the readiness JSON. */ }
      }
      return false;
    }, 'standalone relay binds its actual address');
    if (reopen) assert.equal(info.peer_id, node.peerId, 'Relay identity survives reopen');
    node.peerId = info.peer_id;
    assert.deepEqual(info.protocols, [], 'Standalone relay must not join application gossip');
    assert.ok(info.listen_addresses.includes(`/ip4/127.0.0.1/tcp/${node.p2p}`));
    return;
  }
  const relay = report.nodes[0];
  const routing = index === 1 ? ['--relay-listen',
    `/ip4/127.0.0.1/tcp/${relay.p2p}/p2p/${relay.peerId}/p2p-circuit`] : ['--bootnode', receiverCircuit];
  const child = launch(index, ['run', '--config', join(node.directory, 'node.toml'),
    '--datadir', node.directory, '--keystore', join(node.directory, 'key.json'),
    '--password-file', join(node.directory, 'password'), '--network', 'dev', '--db', 'rocksdb',
    '--chain-id', '1337', '--consensus-engine', 'wpoa', '--block-time', '2000',
    '--max-idle-interval', '1209600000', '--rpc-addr', `127.0.0.1:${node.rpc}`,
    '--metrics-addr', '127.0.0.1:0', '--p2p', '--p2p-addr', `127.0.0.1:${node.p2p}`, ...routing], reopen);
  await until(async () => {
    assert.equal(child.exitCode, null, 'Node exited before RPC readiness');
    try { return await rpc(index, 'eth_chainId'); }
    catch (error) { if (error.cause?.code === 'ECONNREFUSED') return false; throw error; }
  }, 'RPC readiness');
  const info = await rpc(index, 'shell_getNodeInfo');
  if (reopen) assert.equal(info.peer_id, node.peerId, 'Native transport identity survives reopen');
  node.peerId = info.peer_id;
  const stats = await rpc(index, 'shell_getNetworkStats');
  assert.ok(!stats.protocols.includes('mdns') && !stats.protocols.includes('kademlia'),
    'Forced-circuit acceptance disables alternate discovery');
  if (index === 1) {
    receiverCircuit = await until(async () => {
      const log = stripAnsi(await readFile(node.log, 'utf8'));
      const addresses = [...log.matchAll(/Listening on (\S+)/g)].map(match => match[1]);
      const address = addresses.find(address => address.includes('/p2p-circuit'));
      if (!address) return false;
      assert.ok(address.endsWith(`/p2p/${node.peerId}`));
      assert.equal((address.match(/\/p2p\//g) ?? []).length, 2, 'Relay and destination IDs appear once each');
      assert.ok(log.includes('Relay reservation accepted'));
      return address;
    }, 'receiver announces an actually reserved circuit');
    report.receiverCircuit = receiverCircuit;
  }
}
async function stop(index) {
  const item = children.get(index); if (!item) return;
  const { child, opened } = item;
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
    for (let attempt = 0; attempt < 100 && child.exitCode === null && child.signalCode === null; attempt++) await pause(100);
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL'); await new Promise(done => child.once('exit', done));
    }
  }
  opened.exitCode = child.exitCode; opened.signalCode = child.signalCode; opened.endedAt = new Date().toISOString();
  report.nodes[index].exitCode = child.exitCode; children.delete(index);
  assert.equal(child.exitCode, 0, 'Native process must stop cleanly');
}
try {
  for (let index = 0; index < 3; index++) {
    const data = join(directory, `node${index}`); await mkdir(data);
    report.nodes.push({ directory: data, rpc: index ? await freePort() : null, p2p: await freePort() });
    if (!index) {
      // Invalid chain/validator files prove the standalone role does not open them.
      await writeFile(join(data, 'genesis.json'), 'not a chain genesis');
      await writeFile(join(data, 'key.json'), 'not a validator keystore', { mode: 0o600 });
      continue;
    }
    const password = randomBytes(24).toString('hex');
    await writeFile(join(data, 'password'), password, { mode: 0o600 });
    const generated = spawnSync(binary, ['key', 'generate', '--algorithm', 'mldsa65',
      '--output', join(data, 'key.json'), '--password-file', join(data, 'password')],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(generated.status, 0, 'Fresh test key generation failed');
    signers[index] = await sdk.decryptKeystore(JSON.parse(await readFile(join(data, 'key.json'), 'utf8')), password);
    await writeFile(join(data, 'node.toml'), '[p2p]\nenable_mdns = false\nenable_kademlia = false\nenable_dcutr = false\nenable_autonat = false\n');
  }
  const genesis = {
    chain_id: 1337, chain_name: 'relay-circuit-acceptance', network_type: 'Dev',
    timestamp: Math.floor(Date.now() / 1000) - 120, gas_limit: 50000000, extra_data: 'relay-circuit-acceptance',
    alloc: { [signers[2].getAddress()]: { balance: '0x3635c9adc5dea00000', nonce: 0, code: null, storage: null } },
    boot_nodes: [], consensus: { engine: 'wpoa', authorities: [signers[1].getAddress()],
      authority_pubkeys: ['0x' + Buffer.from(signers[1].getPublicKey()).toString('hex')],
      weights: [1], stakes: [], block_time_secs: 2, max_future_secs: 300, epoch_length: 0 },
  };
  for (const node of report.nodes.slice(1)) await writeFile(join(node.directory, 'genesis.json'), JSON.stringify(genesis));
  await start(0); await start(1); await start(2);
  await until(async () => {
    const sender = stripAnsi(await readFile(report.nodes[2].log, 'utf8'));
    const receiver = stripAnsi(await readFile(report.nodes[1].log, 'utf8'));
    return sender.includes('Outbound relay circuit established') && receiver.includes('Inbound relay circuit established');
  }, 'both endpoints authenticate through the relay');
  const recipient = '0x01' + randomBytes(31).toString('hex');
  report.recipient = recipient;
  async function submit(nonce) {
    const tx = sdk.buildTransferTransaction({ chainId: 1337, nonce, to: recipient,
      value: 1n, gasLimit: 21000, maxFeePerGas: 1000000000, maxPriorityFeePerGas: 0 });
    const provider = sdk.createShellProvider({ rpcHttpUrl: `http://127.0.0.1:${report.nodes[2].rpc}` });
    return provider.sendTransaction(await signers[2].buildSignedTransaction({ tx, includePublicKey: true }));
  }
  for (let nonce = 0; nonce < 2; nonce++) {
    if (nonce) {
      await stop(2); await start(2, true);
      assert.equal(await rpc(2, 'eth_getTransactionCount', [signers[2].getAddress(), 'latest']), '0x1');
    }
    const hash = await submit(nonce);
    const receipts = await until(async () => {
      const a = await rpc(1, 'eth_getTransactionReceipt', [hash]);
      const b = await rpc(2, 'eth_getTransactionReceipt', [hash]);
      if (!a || !b) return false;
      assert.equal(a.status, '0x1'); assert.equal(b.status, '0x1'); assert.equal(a.blockHash, b.blockHash);
      return [a, b];
    }, 'genuine signed transfer crosses circuit and follower imports exact receipt');
    assert.equal(await rpc(2, 'eth_getBalance', [recipient, 'latest']), '0x'+(nonce+1).toString(16));
    report.transactions.push({ hash, receipts }); await save();
  }
  await stop(1); await start(1, true);
  assert.equal(await rpc(1, 'eth_getBalance', [recipient, 'latest']), '0x2');
  for (const { hash } of report.transactions) assert.equal((await rpc(1, 'eth_getTransactionReceipt', [hash])).status, '0x1');
  const before = await rpc(1, 'eth_getBlockByNumber', ['latest', false]);
  await stop(0); await pause(2000);
  const pendingHash = await submit(2);
  report.outage = { pendingHash, samples: [] };
  for (let attempt = 0; attempt < 5; attempt++) {
    await pause(1000);
    const receipts = await Promise.all([1,2].map(index => rpc(index, 'eth_getTransactionReceipt', [pendingHash])));
    assert.deepEqual(receipts, [null, null], 'Relay outage must not manufacture an imported receipt');
    assert.equal(await rpc(1, 'eth_getBalance', [recipient, 'latest']), '0x2');
    const current = await rpc(1, 'eth_getBlockByNumber', ['latest', false]);
    assert.equal(current.hash, before.hash);
    report.outage.samples.push({ at: new Date().toISOString(), receipts, hash: current.hash });
  }
  await stop(1); await stop(2); await start(0, true);
  const relayFiles = await readdir(report.nodes[0].directory);
  assert.ok(!relayFiles.includes('db') && !relayFiles.includes('CURRENT'));
  assert.equal(await readFile(join(report.nodes[0].directory, 'genesis.json'), 'utf8'), 'not a chain genesis');
  assert.equal(await readFile(join(report.nodes[0].directory, 'key.json'), 'utf8'), 'not a validator keystore');
  report.circuitConnections = [];
  for (const opened of report.opens.filter(opened => opened.index !== 0)) {
    const peerId = report.nodes[opened.index === 1 ? 2 : 1].peerId;
    const lines = stripAnsi(await readFile(opened.log, 'utf8')).split('\n')
      .filter(line => line.includes(`Connected to ${peerId}`));
    for (const line of lines) {
      assert.ok(line.includes('relayed=true'), 'Application peers must have no direct TCP alternative in this acceptance');
      report.circuitConnections.push({ index: opened.index, peerId, line });
    }
  }
  assert.ok(report.circuitConnections.some(connection => connection.index === 1));
  assert.ok(report.circuitConnections.some(connection => connection.index === 2));
  report.passed = true; report.exitCode = 0;
} catch (error) {
  report.error = { message: error.message, stack: error.stack }; report.exitCode = 1; process.exitCode = 1;
} finally {
  for (const index of [...children.keys()]) {
    try { await stop(index); }
    catch (error) { report.error ??= { message: error.message }; report.exitCode = 1; report.passed = false; process.exitCode = 1; }
  }
  for (const signer of signers) signer?.dispose();
  report.endedAt = new Date().toISOString(); await save();
  console.log(JSON.stringify({ passed: report.passed ?? false, error: report.error?.message,
    signedTransfers: report.transactions.length, nativeOpens: report.opens.length,
    nodeExits: report.opens.map(opened => opened.exitCode) }));
}
