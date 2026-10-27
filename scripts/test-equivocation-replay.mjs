import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import {openSync, closeSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {createServer} from 'node:net';
import {join, resolve} from 'node:path';
import {parseArgs} from 'node:util';
import {createHash} from 'node:crypto';

const {values} = parseArgs({options: {
  'node-bin': {type: 'string'}, 'peer-bin': {type: 'string'}, output: {type: 'string'},
  'old-node-bin': {type: 'string'},
}});
for (const name of ['node-bin', 'peer-bin', 'output']) assert.ok(values[name], `--${name} is required`);
const binary = resolve(values['node-bin']);
const auxiliary = resolve(values['peer-bin']);
const out = resolve(values.output);
await mkdir(out); // A new directory prevents accidental reuse of identities or node data.
const sha = async path => createHash('sha256').update(await readFile(path)).digest('hex');
const result = {startedAt: new Date().toISOString(), binary_sha256: await sha(binary),
  auxiliary_sha256: await sha(auxiliary), observations: [], rpc: [], opens: [], events: []};
let saving = Promise.resolve();
const save = () => saving = saving.then(() => writeFile(join(out, 'result.json'), JSON.stringify(result, null, 2)));
const pause = ms => new Promise(r => setTimeout(r, ms));
let node, helper, port, offender, genesis, fixture, context;
let messages = [];
async function event(type) {
  for (let i = 0; i < 300; i++) {
    const j = messages.findIndex(x => x.event === type);
    if (j >= 0) return messages.splice(j, 1)[0];
    assert.equal(helper.exitCode, null, 'peer exited');
    await pause(100);
  }
  throw Error(`peer event timeout ${type}`);
}
async function freePort() {
  const server = createServer();
  await new Promise((r, j) => {server.once('error', j); server.listen(0, '127.0.0.1', r);});
  const number = server.address().port;
  await new Promise(r => server.close(r));
  return number;
}
async function rpc(method, params = []) {
  const request = {jsonrpc: '2.0', id: result.rpc.length + 1, method, params};
  const response = await (await fetch(`http://127.0.0.1:${port}`, {method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request), signal: AbortSignal.timeout(3000)})).json();
  result.rpc.push({context, request, response});
  await save();
  assert.ok(!response.error, JSON.stringify(response));
  return response.result;
}
async function observe(label, expected, changes = false) {
  // Negative assertions use a full observation window after the peer queues the packet.
  let actual;
  for (let i = 0; i < 20; i++) {
    const info = await rpc('shell_consensusInfo');
    actual = info.validators.find(x => x.address === offender)?.weight;
    if (changes && actual === expected) break;
    if (!changes) assert.equal(actual, expected, label);
    await pause(100);
  }
  result.observations.push({context, label, expected, actual, head: await rpc('eth_getBlockByNumber', ['latest', false])});
  await save();
  assert.equal(actual, expected, label);
}
async function startPeer() {
  messages = [];
  const fd = openSync(join(out, `${context}-peer.log`), 'w');
  helper = spawn(auxiliary, [], {stdio: ['pipe', 'pipe', fd]}); closeSync(fd);
  result.opens.push({context, label: 'peer', pid: helper.pid, argv: [auxiliary]});
  createInterface({input: helper.stdout}).on('line', line => {
    const value = JSON.parse(line); messages.push(value); result.events.push({context, ...value});
  });
  return event('ready');
}
async function stop(child, label) {
  if (!child) return;
  if (child.exitCode === null && child.signalCode === null) {
    if (label === 'peer') child.stdin.end(JSON.stringify({action: 'stop'}) + '\n');
    else child.kill('SIGTERM');
    await new Promise((r, j) => {
      const timer = setTimeout(() => j(Error(`stop timeout ${label}`)), 20000);
      child.once('exit', () => {clearTimeout(timer); r();});
    });
  }
  Object.assign(result.opens.find(x => x.pid === child.pid), {exit_code: child.exitCode, signal: child.signalCode});
  await save(); assert.equal(child.exitCode, 0, `${label} exit`);
}
async function startNode(data) {
  port = await freePort();
  const args = ['--datadir', data, 'run', '--node-role', 'prover', '--network', 'dev', '--db', 'rocksdb',
    '--rpc-addr', `127.0.0.1:${port}`, '--metrics-addr', '127.0.0.1:0', '--p2p', '--p2p-addr', '127.0.0.1:0',
    '--enable-stark-aggregation', 'false', '--log-level', 'info'];
  const logPath = join(out, `${context}-node.log`);
  const fd = openSync(logPath, 'w');
  node = spawn(binary, args, {stdio: ['ignore', fd, fd]}); closeSync(fd);
  result.opens.push({context, label: 'node', pid: node.pid, argv: [binary, ...args]}); await save();
  let bootnode;
  for (let i = 0; i < 150; i++) {
    assert.equal(node.exitCode, null, 'node exited');
    try {
      if (await rpc('eth_chainId') === '0x539') {
        bootnode = (await readFile(logPath, 'utf8')).match(/Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[a-zA-Z0-9]+)/)?.[1];
        if (bootnode) return bootnode;
      }
    } catch (error) {if (error.code === 'ERR_ASSERTION') throw error;}
    await pause(100);
  }
  throw Error('RPC/P2P startup timeout');
}
async function connect(bootnode, saved) {
  const genesisBlock = await rpc('eth_getBlockByNumber', ['0x0', false]);
  helper.stdin.write(JSON.stringify({action: 'init', bootnode, parent_hash: genesisBlock.hash,
    timestamp: genesis.timestamp + 2, ...(saved ? {fixture: saved} : {})}) + '\n');
  return (await event('peered')).fixture;
}
async function command(executable, args, expected = 0) {
  const logPath = join(out, `${context}-command.log`);
  const fd = openSync(logPath, 'w');
  const child = spawn(executable, args, {stdio: ['ignore', fd, fd]}); closeSync(fd);
  const receipt = {context, label: 'command', pid: child.pid, argv: [executable, ...args], startedAt: new Date().toISOString()};
  result.opens.push(receipt); await save();
  await new Promise((r, j) => {
    const timer = setTimeout(() => {child.kill('SIGTERM'); j(Error('command timeout'));}, 30000);
    child.once('exit', () => {clearTimeout(timer); r();});
  });
  Object.assign(receipt, {exit_code: child.exitCode, signal: child.signalCode, endedAt: new Date().toISOString()});
  await save(); assert.equal(child.exitCode, expected, context);
  return readFile(logPath, 'utf8');
}
async function send(kind, expected, changes = false) {
  const logPath = join(out, `${context}-node.log`);
  const pattern = kind === 'invalid' ? /received invalid signed equivocation evidence/g : /signed equivocation evidence verified/g;
  const before = ((await readFile(logPath, 'utf8')).match(pattern) ?? []).length;
  helper.stdin.write(JSON.stringify({action: 'send', kind}) + '\n');
  await event('queued');
  let processed = false;
  for (let i = 0; i < 100; i++) {
    if (((await readFile(logPath, 'utf8')).match(pattern) ?? []).length > before) {processed = true; break;}
    await pause(100);
  }
  assert.ok(processed, `native authentication did not observe ${kind}`);
  await observe(kind, expected, changes);
}
try {
  // Both protected observers receive exactly the same genuine signed evidence.
  for (const name of ['protected-a', 'protected-b', 'legacy']) {
    context = `${name}-first`;
    const ready = await startPeer();
    if (!genesis) {
      offender = ready.offender;
      genesis = {chain_id: 1337, chain_name: 'equivocation-replay-acceptance', network_type: 'Dev',
        timestamp: Math.floor(Date.now() / 1000) - 5, gas_limit: 30000000,
        extra_data: 'equivocation-replay-acceptance', registered_key_algorithm_height: 0,
        consensus: {engine: 'wpoa', authorities: [offender], authority_pubkeys: [ready.public_key],
          weights: [100], stakes: [], block_time_secs: 2, max_future_secs: 300, epoch_length: 0}, alloc: {}, boot_nodes: []};
    }
    const data = join(out, name); await mkdir(data);
    const protectedChain = name !== 'legacy';
    await writeFile(join(data, 'genesis.json'), JSON.stringify({...genesis,
      ...(protectedChain ? {equivocation_replay_height: 0} : {})}, null, 2));
    const bootnode = await startNode(data); await observe('initial', 100);
    fixture = await connect(bootnode, fixture); result.fixture = fixture; result.offender = offender;
    await send('invalid', 100);
    await send('first', 90, true);
    await send('reversed', protectedChain ? 90 : 81, !protectedChain);
    if (protectedChain) await send('first', 90);
    await stop(helper, 'peer'); helper = undefined; await stop(node, 'node'); node = undefined;
    if (protectedChain) {
      context = `${name}-reopen`; await startPeer();
      const reopened = await startNode(data); await observe('recovered', 90);
      await connect(reopened, fixture);
      await send('reversed', 90);
      await send('distinct', 81, true);
      await send('distinct', 81);
      await stop(helper, 'peer'); helper = undefined; await stop(node, 'node'); node = undefined;
      context = `${name}-final-reopen`;
      await startNode(data); await observe('distinct-recovered', 81);
      await stop(node, 'node'); node = undefined;
    }
  }
  // Export/import must carry the replay records together with the adjusted weights.
  const source = join(out, 'protected-a');
  const snapshot = join(out, 'penalties.snapshot');
  context = 'snapshot-export'; await command(binary, ['--datadir', source, 'export-state', '--output', snapshot]);
  const restored = join(out, 'snapshot-restored'); await mkdir(restored);
  await writeFile(join(restored, 'genesis.json'), await readFile(join(source, 'genesis.json')));
  context = 'snapshot-import'; await command(binary, ['--datadir', restored, 'import-state', '--snapshot', snapshot]);
  context = 'snapshot-reopen'; await startPeer();
  const restoredPeer = await startNode(restored); await observe('snapshot-weight', 81);
  await connect(restoredPeer, fixture); await send('first', 81); await send('distinct', 81);
  await stop(helper, 'peer'); helper = undefined; await stop(node, 'node'); node = undefined;
  if (values['old-node-bin']) {
    const oldBinary = resolve(values['old-node-bin']); result.old_binary_sha256 = await sha(oldBinary);
    context = 'old-writer-refusal';
    const log = await command(oldBinary, ['--datadir', source, 'run', '--node-role', 'prover',
      '--network', 'dev', '--db', 'rocksdb', '--rpc-addr', '127.0.0.1:0',
      '--metrics-addr', '127.0.0.1:0', '--enable-stark-aggregation', 'false'], 1);
    assert.match(log, /invalid challenge snapshot/);
    context = 'after-old-writer'; await startNode(source); await observe('penalties-intact', 81);
    await stop(node, 'node'); node = undefined;
  }
  result.passed = true;
} catch (error) {result.error = error.stack; process.exitCode = 1;}
finally {
  try {await stop(helper, 'peer');} finally {await stop(node, 'node');}
  result.endedAt = new Date().toISOString(); await save();
  console.log(JSON.stringify({passed: result.passed, error: result.error,
    observations: result.observations.map(({context, label, expected, actual}) => ({context, label, expected, actual})), output: out}));
}
