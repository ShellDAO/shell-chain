// Manual acceptance for Kademlia discovery through a shared seed.
// Requires a RocksDB/libp2p shell-node and installed shell-sdk@0.14.0-rc.3.
// NODE_BIN=/path/to/shell-node SHELL_SDK_ENTRY=/path/to/shell-sdk/dist/index.js \
//   node tests/e2e/native-kademlia-discovery.mjs
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openSync, closeSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

assert.ok(process.env.NODE_BIN && process.env.SHELL_SDK_ENTRY,
  'Set NODE_BIN and SHELL_SDK_ENTRY to the node and installed SDK');
const binary = resolve(process.env.NODE_BIN);
const sdk = await import(pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)));
const directory = await mkdtemp(join(tmpdir(), 'shell-kad-discovery-'));
const report = { startedAt: new Date().toISOString(), nodes: [], transactions: [] };
const signers = [];
const children = new Map();
const pause = ms => new Promise(done => setTimeout(done, ms));
let requestId = 0;
const allocatedPorts = new Set();
const save = () => writeFile(join(directory, 'report.json'), JSON.stringify(report, null, 2));
async function freePort() {
  const listener = createServer();
  await new Promise((done, fail) => {
    listener.once('error', fail); listener.listen(0, '127.0.0.1', done);
  });
  const port = listener.address().port;
  await new Promise(done => listener.close(done));
  if (allocatedPorts.has(port)) return freePort();
  allocatedPorts.add(port);
  return port;
}
async function rpc(index, method, params = []) {
  await pause(50);
  const answer = await (await fetch(`http://127.0.0.1:${report.nodes[index].rpc}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++requestId, method, params }),
    signal: AbortSignal.timeout(10000),
  })).json();
  assert.equal(answer.error, undefined, JSON.stringify(answer.error));
  return answer.result;
}
async function until(check, label) {
  for (let attempt = 0; attempt < 120; attempt++) {
    const result = await check();
    if (result) return result;
    await pause(200);
  }
  throw Error(`Timed out: ${label}`);
}
async function start(index, reopen = false) {
  const node = report.nodes[index];
  // Keep persisted identity/state while avoiding immediate TCP source-port reuse.
  if (reopen) { node.rpc = await freePort(); node.p2p = await freePort(); }
  const boot = index === 0 ? [] : ['--bootnode',
    `/ip4/127.0.0.1/tcp/${report.nodes[0].p2p}/p2p/${report.nodes[0].peerId}`];
  const args = ['run', '--datadir', node.directory, '--keystore', join(node.directory, 'key.json'),
    '--password-file', join(node.directory, 'password'), '--network', 'dev', '--db', 'rocksdb',
    '--chain-id', '1337', '--consensus-engine', 'wpoa', '--block-time', '2000',
    '--max-idle-interval', '1209600000', '--rpc-addr', `127.0.0.1:${node.rpc}`,
    '--metrics-addr', '127.0.0.1:0', '--p2p', '--p2p-addr', `127.0.0.1:${node.p2p}`, ...boot];
  const fd = openSync(join(node.directory, reopen ? 'reopen.log' : 'node.log'), 'wx');
  const child = spawn(binary, args, { env: { ...process.env, RUST_LOG: 'info,shell_network=debug,libp2p_kad=debug,libp2p_identify=debug' }, stdio: ['ignore', fd, fd] });
  closeSync(fd); children.set(index, child);
  let spawnError;
  child.once('error', error => { spawnError = error; });
  await until(async () => {
    if (spawnError) throw spawnError;
    assert.equal(child.exitCode, null, 'Node exited before RPC readiness');
    try { return await rpc(index, 'eth_chainId'); }
    catch (error) { if (error.cause?.code === 'ECONNREFUSED') return false; throw error; }
  }, 'RPC readiness');
  const info = await rpc(index, 'shell_getNodeInfo');
  assert.ok(info.peer_id);
  if (reopen) assert.equal(info.peer_id, node.peerId, 'Transport identity survives restart');
  node.peerId = info.peer_id;
}
async function stop(index) {
  const child = children.get(index);
  if (!child) return;
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
    for (let attempt = 0; attempt < 100 && child.exitCode === null && child.signalCode === null; attempt++) await pause(100);
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL'); await new Promise(done => child.once('exit', done));
    }
  }
  report.nodes[index].exitCode = child.exitCode;
  children.delete(index);
  assert.equal(child.exitCode, 0, 'Native node must stop cleanly');
}
try {
  for (let index = 0; index < 3; index++) {
    const data = join(directory, `node${index}`);
    await mkdir(data);
    const password = randomBytes(24).toString('hex');
    await writeFile(join(data, 'password'), password, { mode: 0o600 });
    const generated = spawnSync(binary, ['key', 'generate', '--algorithm', 'mldsa65',
      '--output', join(data, 'key.json'), '--password-file', join(data, 'password')],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(generated.status, 0, 'Fresh validator generation failed');
    signers.push(await sdk.decryptKeystore(JSON.parse(await readFile(join(data, 'key.json'), 'utf8')), password));
    report.nodes.push({ directory: data, rpc: await freePort(), p2p: await freePort() });
  }
  const authority = signers[2].getAddress();
  const genesis = {
    chain_id: 1337, chain_name: 'peer-bandwidth-acceptance', network_type: 'Dev',
    timestamp: Math.floor(Date.now() / 1000) - 120, gas_limit: 50000000,
    extra_data: 'peer-bandwidth-acceptance',
    alloc: { [authority]: { balance: '0x3635c9adc5dea00000', nonce: 0, code: null, storage: null } },
    boot_nodes: [], consensus: { engine: 'wpoa', authorities: [authority],
      authority_pubkeys: ['0x' + Buffer.from(signers[2].getPublicKey()).toString('hex')],
      weights: [1], stakes: [], block_time_secs: 2, max_future_secs: 300, epoch_length: 0 },
  };
  for (const node of report.nodes) await writeFile(join(node.directory, 'genesis.json'), JSON.stringify(genesis));
  await start(0); await start(1);
  await until(async () => (await rpc(0, 'shell_getNodeInfo')).peerCount === 1, 'first leaf connects to seed');
  await pause(3000); await start(2);

  const provider = sdk.createShellProvider({ rpcHttpUrl: `http://127.0.0.1:${report.nodes[2].rpc}` });
  async function transfer(nonce) {
    const tx = sdk.buildTransferTransaction({ chainId: 1337, nonce, to: signers[1].getAddress(), value: 1n, gasLimit: 21000, maxFeePerGas: 1000000000, maxPriorityFeePerGas: 0 });
    const hash = await provider.sendTransaction(await signers[2].buildSignedTransaction({ tx, includePublicKey: true }));
    const receipts = await until(async () => {
      const a = await rpc(2, 'eth_getTransactionReceipt', [hash]);
      const b = await rpc(1, 'eth_getTransactionReceipt', [hash]);
      if (!a || !b) return false;
      assert.equal(a.status, '0x1'); assert.equal(b.status, '0x1'); assert.equal(a.blockHash, b.blockHash); return [a,b];
    }, 'signed transfer independently imported');
    assert.equal(await rpc(1, 'eth_getBalance', [signers[1].getAddress(), 'latest']), '0x'+(nonce+1).toString(16));
    report.transactions.push({hash,receipts}); await save();
  }
  await transfer(0);
  report.discoverySamples=[];
  const started=Date.now(); let discovered=false;
  while(Date.now()-started < 330000) {
    const stats=await Promise.all([0,1,2].map(index=>rpc(index,'shell_getNetworkStats')));
    report.discoverySamples.push({at:new Date().toISOString(),stats}); await save();
    if(stats[1].peerCount>=2 && stats[2].peerCount>=2){discovered=true;break;}
    await pause(5000);
  }
  assert.ok(discovered, 'Kademlia must discover and connect the other leaf from the shared seed within a normal bootstrap interval');
  await stop(0); await pause(2000); await transfer(1);
  await stop(1); await start(1,true);
  assert.equal(await rpc(1,'eth_getBalance',[signers[1].getAddress(),'latest']),'0x2');
  report.passed=true; report.exitCode=0;
} catch (error) {
  report.error = { message: error.message, stack: error.stack };
  report.exitCode = 1; process.exitCode = 1;
} finally {
  for (const index of [...children.keys()]) {
    try { await stop(index); }
    catch (error) { report.error ??= { message: error.message }; report.exitCode = 1; report.passed = false; process.exitCode = 1; }
  }
  for (const signer of signers) signer.dispose();
  report.endedAt = new Date().toISOString(); await save();
  console.log(JSON.stringify({ passed: report.passed ?? false, error: report.error?.message,
    signedTransactions: report.transactions.length, nodeExits: report.nodes.map(node => node.exitCode) }));
}
