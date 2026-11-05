#!/usr/bin/env node
// Live P2P listener truthfulness through signed import and persistent reopen.
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir, mkdtemp, cp } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { createServer, createConnection } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
assert.ok(
  process.env.SHELL_SDK_ENTRY,
  "Set SHELL_SDK_ENTRY to a compatible built SDK dist/index.js",
);
const {
  createShellProvider,
  createShellPublicClient,
  decryptKeystore,
  buildTransaction,
} = await import(pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)));
const binary = resolve(process.env.NODE_BIN ?? "target/debug/shell-node");
const out = await mkdtemp(join(tmpdir(), "shell-native-network-listening-"));
const result = {
  startedAt: new Date().toISOString(),
  commands: [],
  rpc: [],
  services: [],
  listeners: [],
  closedListeners: [],
};
const save = () =>
  writeFile(join(out, "runtime.json"), JSON.stringify(result, null, 2));
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const passwordPath = join(out, "password.txt"),
  rootKey = join(out, "root.json"),
  observerKey = join(out, "observer.json");
const observerDir = join(out, "observer"),
  producerDir = join(out, "producer");
const nodes = new Map();
let signer;
function cli(args, label) {
  const child = spawnSync(binary, args, { encoding: "utf8" });
  result.commands.push({
    label,
    argv: args,
    exit_code: child.status,
    stdout: "[key output omitted]",
    stderr: child.stderr,
  });
  assert.equal(child.status, 0, child.stderr);
}
async function port() {
  const server = createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const value = server.address().port;
  await new Promise((r) => server.close(r));
  return value;
}
async function call(node, method, params = []) {
  const input = { jsonrpc: "2.0", id: result.rpc.length + 1, method, params };
  const response = await fetch(node.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
    signal: AbortSignal.timeout(10000),
  });
  const text = await response.text();
  let output;
  try {
    output = JSON.parse(text);
  } catch {
    output = { nonJsonBody: text };
  }
  result.rpc.push({ node: node.name, input, http: response.status, output });
  assert.equal(response.status, 200, `RPC HTTP ${response.status}: ${text}`);
  assert.ok(
    !Object.hasOwn(output, "nonJsonBody"),
    "RPC returned non-JSON body",
  );
  return output;
}
async function rpc(node, method, params = []) {
  const output = await call(node, method, params);
  if (output.error) throw Error(JSON.stringify(output.error));
  return output.result;
}
async function start(name, dir, key, bootnode, enabled = true) {
  const rpcPort = await port(),
    p2pPort = await port();
  const args = [
    "run",
    "--datadir",
    dir,
    "--keystore",
    key,
    "--password-file",
    passwordPath,
    "--network",
    "dev",
    "--chain-id",
    "1337",
    "--consensus-engine",
    "wpoa",
    "--block-time",
    "1000",
    "--max-idle-interval",
    "1209600000",
    "--db",
    "rocksdb",
    "--storage-profile",
    "full",
    "--rpc-addr",
    `127.0.0.1:${rpcPort}`,
    "--metrics-addr",
    "127.0.0.1:0",
    "--rpc-api",
    "eth,net,web3,shell,admin",
    "--rpc-rate-limit",
    "1000",
    "--p2p-addr",
    `127.0.0.1:${enabled ? 0 : p2pPort}`,
  ];
  if (enabled) args.push("--p2p");
  if (key === observerKey) args.push("--node-role", "prover");
  if (bootnode) args.push("--bootnode", bootnode);
  const fd = openSync(join(out, name + ".log"), "w");
  const child = spawn(binary, args, { stdio: ["ignore", fd, fd] });
  closeSync(fd);
  const node = {
    name,
    dir,
    child,
    url: `http://127.0.0.1:${rpcPort}`,
    p2pPort,
    enabled,
    boundPort: null,
  };
  nodes.set(name, node);
  result.services.push({ name, argv: args, pid: child.pid });
  await save();
  for (let n = 0; n < 120; n++) {
    assert.equal(child.exitCode, null, "node exited before RPC");
    try {
      if ((await rpc(node, "eth_chainId")) === "0x539") return node;
    } catch {}
    await pause(250);
  }
  throw Error("native startup timeout: " + name);
}
async function stop(name) {
  const node = nodes.get(name);
  if (!node) return;
  if (node.child.exitCode === null && node.child.signalCode === null) {
    node.child.kill("SIGTERM");
    await new Promise((r) => node.child.once("exit", r));
  }
  result.services.find((v) => v.pid === node.child.pid).exit = {
    code: node.child.exitCode,
    signal: node.child.signalCode,
  };
  nodes.delete(name);
  await save();
}
async function state(node) {
  const block = await rpc(node, "eth_getBlockByNumber", ["latest", false]);
  const finalized = await rpc(node, "eth_getBlockByNumber", [
    "finalized",
    false,
  ]);
  return {
    number: block.number,
    hash: block.hash,
    root: block.stateRoot,
    finalized: finalized.hash,
    nonce: await rpc(node, "eth_getTransactionCount", [
      signer.getAddress(),
      "latest",
    ]),
    balance: await rpc(node, "eth_getBalance", [signer.getAddress(), "latest"]),
    recipientBalance: await rpc(node, "eth_getBalance", [
      result.recipient,
      "latest",
    ]),
  };
}
async function tcp(port) {
  return new Promise((resolve) => {
    const socket = createConnection({host:"127.0.0.1",port});
    socket.once("connect",()=>{socket.destroy();resolve({connected:true})});
    socket.once("error",(error)=>resolve({connected:false,code:error.code}));
    socket.setTimeout(2000,()=>{socket.destroy();resolve({connected:false,code:"timeout"})});
  });
}
async function listener(node, expected) {
  const before = await state(node);
  let stats;
  for(let i=0;i<120;i++) {
    stats = await rpc(node,"shell_getNetworkStats");
    if(!expected || stats.listeningAddress)break;
    await pause(50);
  }
  const raw = await rpc(node,"net_listening");
  const sdk = await createShellPublicClient({rpcHttpUrl:node.url}).request({method:"net_listening",params:[]});
  let probe;
  if(expected) {
    const match = /^\/ip4\/127\.0\.0\.1\/tcp\/(\d+)$/.exec(stats.listeningAddress);
    assert.ok(match,"actual bound loopback TCP address");
    node.boundPort=Number(match[1]);
    assert.ok(node.boundPort>0);
    probe=await tcp(node.boundPort);
  } else {
    assert.equal(stats.listeningAddress,"");
    probe=await tcp(node.p2pPort);
  }
  result.listeners.push({node:node.name,expected,raw,sdk,stats,tcp:probe});
  assert.equal(raw,expected);
  assert.equal(sdk,expected);
  assert.equal(probe.connected,expected);
  if(!expected)assert.equal(probe.code,"ECONNREFUSED");
  assert.deepEqual(await state(node),before,"listener reads leave state unchanged");
}
async function closed(node) {
  const probe=await tcp(node.boundPort);
  result.closedListeners.push({node:node.name,port:node.boundPort,tcp:probe});
  assert.deepEqual(probe,{connected:false,code:"ECONNREFUSED"});
}
try {
  const old = process.env.SHELL_LISTENING_SOURCE_FIXTURE;
  if (old) {
    const prior = JSON.parse(await readFile(join(old, "runtime.json"), "utf8"));
    assert.ok(prior.nodesStopped);
    await cp(join(old, "observer"), observerDir, { recursive: true });
    await cp(join(old, "root.json"), rootKey);
    await cp(join(old, "password.txt"), passwordPath);
    await cp(join(old, "observer.json"), observerKey);
    result.recipient = prior.recipient ?? "0x" + randomBytes(32).toString("hex");
  } else {
    await mkdir(observerDir);
    await writeFile(passwordPath, randomBytes(24).toString("hex"), {
      mode: 0o600,
    });
    cli(
      [
        "--password-file",
        passwordPath,
        "key",
        "generate",
        "--algorithm",
        "mldsa65",
        "--output",
        rootKey,
      ],
      "root keygen",
    );
    result.recipient = "0x" + randomBytes(32).toString("hex");
  }
  signer = await decryptKeystore(
    JSON.parse(await readFile(rootKey, "utf8")),
    await readFile(passwordPath, "utf8"),
  );
  try {
    await readFile(observerKey);
  } catch {
    cli(
      [
        "--password-file",
        passwordPath,
        "key",
        "generate",
        "--algorithm",
        "mldsa65",
        "--output",
        observerKey,
      ],
      "observer keygen",
    );
  }
  if (!old) {
    await writeFile(
      join(observerDir, "genesis.json"),
      JSON.stringify(
        {
          chain_id: 1337,
          chain_name: "native-network-listening",
          network_type: "Dev",
          timestamp: Math.floor(Date.now() / 1000) - 60,
          gas_limit: 30000000,
          extra_data: "native-network-listening",
          boot_nodes: [],
          bloom_activation_height: 0,
          fee_accounting_activation_height: 0,
          alloc: {
            [signer.getAddress()]: {
              balance: "0x3635c9adc5dea00000",
              nonce: 0,
              code: null,
              storage: null,
            },
          },
          consensus: {
            engine: "wpoa",
            authorities: [signer.getAddress()],
            authority_pubkeys: [
              "0x" + Buffer.from(signer.getPublicKey()).toString("hex"),
            ],
            weights: [1],
            stakes: [],
            block_time_secs: 1,
            max_future_secs: 300,
            epoch_length: 0,
          },
        },
        null,
        2,
      ),
    );
  }
  // Copy chain state only: each live node must own a separate P2P identity.
  await mkdir(producerDir);
  try {
    await cp(join(observerDir, "db"), join(producerDir, "db"), {
      recursive: true,
    });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  await cp(
    join(observerDir, "genesis.json"),
    join(producerDir, "genesis.json"),
  );
  const off=await start("without-p2p",observerDir,observerKey,undefined,false);
  console.log(`Acceptance artifacts: ${out}`);
  result.before=await state(off);
  await listener(off,false);
  assert.equal(await rpc(off,"net_peerCount"),"0x0");
  await stop(off.name);
  const observer=await start("observer",observerDir,observerKey);
  assert.deepEqual(await state(observer),result.before);
  assert.equal(await rpc(observer,"net_peerCount"),"0x0");
  await listener(observer,true);
  const signed=await signer.buildSignedTransaction({tx:buildTransaction({chainId:1337,nonce:Number(BigInt(result.before.nonce)),to:result.recipient,value:31n,data:"0x",gasLimit:1000000}),includePublicKey:true});
  const hash=await createShellProvider({rpcHttpUrl:observer.url}).sendTransaction(signed);
  result.sentHash=hash;
  assert.deepEqual(await state(observer),result.before);
  assert.equal(await rpc(observer,"eth_getTransactionReceipt",[hash]),null);
  const identity=await rpc(observer,"admin_nodeInfo");
  const producer=await start("producer",producerDir,rootKey,`/ip4/127.0.0.1/tcp/${observer.boundPort}/p2p/${identity.id}`);
  const producerIdentity=await rpc(producer,"admin_nodeInfo");
  assert.notEqual(producerIdentity.id,identity.id);
  result.peerIdentities=[identity.id,producerIdentity.id];
  const until=Date.now()+90000;
  let receipt;
  while(!(receipt=await rpc(observer,"eth_getTransactionReceipt",[hash]))) {
    assert.ok(Date.now()<until,"genuine signed transaction imported");await pause(250);
  }
  assert.equal(receipt.status,"0x1");
  for(const node of [observer,producer]) {
    while((await state(node)).finalized!==receipt.blockHash) {
      assert.ok(Date.now()<until,"both nodes finalized same signed block");await pause(250);
    }
    assert.ok(BigInt(await rpc(node,"net_peerCount"))>0n);
    await listener(node,true);
  }
  result.after=await state(observer);
  assert.deepEqual(await state(producer),result.after);
  assert.equal(BigInt(result.after.recipientBalance),BigInt(result.before.recipientBalance)+31n);
  assert.equal(BigInt(result.after.nonce),BigInt(result.before.nonce)+1n);
  result.receipt=receipt;
  await stop(observer.name);await closed(observer);
  const reopenedOff=await start("reopened-off",observerDir,observerKey,undefined,false);
  await listener(reopenedOff,false);
  assert.deepEqual(await state(reopenedOff),result.after);
  assert.deepEqual(await rpc(reopenedOff,"eth_getTransactionReceipt",[hash]),receipt);
  await stop(reopenedOff.name);
  const reopenedOn=await start("reopened-on",observerDir,observerKey);
  await listener(reopenedOn,true);
  assert.deepEqual(await state(reopenedOn),result.after);
  assert.deepEqual(await rpc(reopenedOn,"eth_getTransactionReceipt",[hash]),receipt);
  await stop(reopenedOn.name);await closed(reopenedOn);
  await stop(producer.name);await closed(producer);
  result.passed=true;
} catch(error) {
  result.error=String(error);process.exitCode=1;
} finally {
  for(const name of [...nodes.keys()])await stop(name);
  result.nodesStopped=nodes.size===0;
  result.endedAt=new Date().toISOString();await save();signer?.dispose();
  console.log(`Acceptance report: ${join(out,"runtime.json")}`);
}
