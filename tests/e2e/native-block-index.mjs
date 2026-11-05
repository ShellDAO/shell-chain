#!/usr/bin/env node
// Transaction-by-block/index RPCs over real signed pending/imported/persisted state.
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir, mkdtemp, cp } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { createServer } from "node:net";
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
const out = await mkdtemp(join(tmpdir(), "shell-native-block-index-"));
const result = {
  startedAt: new Date().toISOString(),
  commands: [],
  rpc: [],
  services: [],
  phases: [],
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
async function start(name, dir, key, bootnode) {
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
    "--p2p",
    "--p2p-addr",
    `127.0.0.1:${p2pPort}`,
  ];
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
async function transactions(node, tag, block) {
  const before = await state(node);
  const client = createShellPublicClient({ rpcHttpUrl: node.url });
  const selected = [];
  for (const [index, hash] of block.transactions.entries()) {
    const quantity = "0x" + index.toString(16);
    const byNumber = await rpc(node, "eth_getTransactionByBlockNumberAndIndex", [tag, quantity]);
    const byHash = await rpc(node, "eth_getTransactionByBlockHashAndIndex", [block.hash, quantity]);
    assert.deepEqual(byHash, byNumber);
    assert.equal(byHash.hash, hash);
    assert.equal(byHash.blockHash, block.hash);
    assert.equal(byHash.blockNumber, block.number);
    assert.equal(byHash.transactionIndex, quantity);
    if (BigInt(byHash.type) < 0x80n) {
      const offered = BigInt(byHash.maxFeePerGas);
      const uncapped = BigInt(block.baseFeePerGas) + BigInt(byHash.maxPriorityFeePerGas);
      assert.equal(BigInt(byHash.gasPrice), offered < uncapped ? offered : uncapped);
    }
    if (hash === result.sentHash) {
      assert.equal(byHash.from, signer.getAddress());
      assert.equal(byHash.to, result.recipient);
      assert.equal(byHash.value, "0x1d");
      assert.equal(byHash.nonce, result.before.nonce);
      assert.equal(byHash.input, "0x");
    }
    const legacy = await rpc(node, "eth_getTransactionByHash", [hash]);
    // Hash lookups can report a storage-relative user index. Compare payload
    // fields separately and independently assert the absolute block position.
    assert.deepEqual({ ...legacy, transactionIndex: quantity }, byHash);
    for (const lookup of [{blockNumber:BigInt(block.number),index}, {blockHash:block.hash,index}]) {
      const tx = await client.getTransaction(lookup);
      assert.equal(tx.hash, hash);
      assert.equal(tx.blockHash, block.hash);
      assert.equal(tx.blockNumber, BigInt(block.number));
      assert.equal(tx.transactionIndex, index);
    }
    selected.push(byHash);
  }
  assert.equal(await rpc(node, "eth_getTransactionByBlockNumberAndIndex", [tag, "0x" + block.transactions.length.toString(16)]), null);
  assert.equal(await rpc(node, "eth_getTransactionByBlockHashAndIndex", [block.hash, "0xffffffffffffffff"]), null);
  assert.deepEqual(await state(node), before, "transaction lookups are read-only");
  result.phases.push({node:node.name, tag, hash:block.hash, selected});
}

try {
  const old = process.env.SHELL_INDEX_SOURCE_FIXTURE;
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
          chain_name: "native-block-index",
          network_type: "Dev",
          timestamp: Math.floor(Date.now() / 1000) - 60,
          gas_limit: 30000000,
          extra_data: "native-block-index",
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
  const observer = await start("observer", observerDir, observerKey);
  console.log(`Acceptance artifacts: ${out}`);
  result.before = await state(observer);
  const firstBlock = await rpc(observer, "eth_getBlockByNumber", [result.before.number, false]);
  result.originalBlock = firstBlock;
  await save();
  if (firstBlock.transactions.length) {
    // Revisit the exact original SDK call before submitting a new intent.
    const client = createShellPublicClient({ rpcHttpUrl: observer.url });
    assert.equal((await client.getTransaction({blockNumber:BigInt(firstBlock.number),index:0})).hash, firstBlock.transactions[0]);
  }
  await transactions(observer, firstBlock.number, firstBlock);
  const genesis = await rpc(observer, "eth_getBlockByNumber", ["earliest", false]);
  await transactions(observer, "earliest", genesis);
  for (const tag of ["latest", "safe", "finalized"])
    if (firstBlock.transactions.length)
      assert.equal((await rpc(observer, "eth_getTransactionByBlockNumberAndIndex", [tag,"0x0"])).hash,firstBlock.transactions[0]);
  assert.equal(await rpc(observer, "eth_getTransactionByBlockNumberAndIndex", ["0xffffffffffffffff","0x0"]), null);
  assert.equal(await rpc(observer, "eth_getTransactionByBlockHashAndIndex", ["0x"+"ff".repeat(32),"0x0"]), null);
  assert.equal((await call(observer, "eth_getTransactionByBlockHashAndIndex", ["0x1234","0x0"])).error?.code,-32602);
  for (const bad of ["0x", "0x00", "0x01", "1", "-1", "0xg", "0x10000000000000000"])
    assert.equal((await call(observer, "eth_getTransactionByBlockNumberAndIndex", ["latest",bad])).error?.code,-32602);
  assert.equal((await call(observer, "eth_getTransactionByBlockNumberAndIndex", ["bad-tag","0x0"])).error?.code,-32602);
  assert.deepEqual(await state(observer),result.before);
  const signed = await signer.buildSignedTransaction({
    tx: buildTransaction({
      chainId: 1337,
      nonce: Number(BigInt(result.before.nonce)),
      to: result.recipient,
      value: 29n,
      data: "0x",
      gasLimit: 1000000,
    }),
    includePublicKey: true,
  });
  const hash = await createShellProvider({
    rpcHttpUrl: observer.url,
  }).sendTransaction(signed);
  result.sentHash = hash;
  await save();
  const pending = await rpc(observer, "eth_getBlockByNumber", [
    "pending",
    false,
  ]);
  assert.deepEqual(pending.transactions, [hash]);
  const pendingTx = await rpc(observer, "eth_getTransactionByBlockNumberAndIndex", ["pending","0x0"]);
  assert.equal(pendingTx.hash,hash);
  assert.equal(pendingTx.value,"0x1d");
  assert.equal(pendingTx.from,signer.getAddress());
  assert.equal(pendingTx.to,result.recipient);
  assert.deepEqual([pendingTx.blockHash,pendingTx.blockNumber,pendingTx.transactionIndex],[null,null,null]);
  assert.equal(await rpc(observer,"eth_getTransactionByBlockNumberAndIndex",["pending","0x1"]),null);
  const pendingSDK=await createShellPublicClient({rpcHttpUrl:observer.url}).getTransaction({blockTag:"pending",index:0});
  assert.equal(pendingSDK.hash,hash);
  assert.deepEqual([pendingSDK.blockHash,pendingSDK.blockNumber,pendingSDK.transactionIndex],[null,null,null]);
  result.pending=pendingTx;
  assert.deepEqual(await state(observer), result.before);
  assert.equal(await rpc(observer, "eth_getTransactionReceipt", [hash]), null);
  const identity = await rpc(observer, "admin_nodeInfo");
  const producer = await start(
    "producer",
    producerDir,
    rootKey,
    `/ip4/127.0.0.1/tcp/${observer.p2pPort}/p2p/${identity.id}`,
  );
  const producerIdentity = await rpc(producer, "admin_nodeInfo");
  assert.notEqual(
    producerIdentity.id,
    identity.id,
    "independent P2P identities",
  );
  result.peerIdentities = [identity.id, producerIdentity.id];
  const until = Date.now() + 90000;
  let receipt;
  while (
    !(receipt = await rpc(observer, "eth_getTransactionReceipt", [hash]))
  ) {
    assert.ok(Date.now() < until, "genuine pending transaction imported");
    await pause(250);
  }
  assert.equal(receipt.status, "0x1");
  for (const node of [observer, producer]) {
    while ((await state(node)).finalized !== receipt.blockHash) {
      assert.ok(Date.now() < until, "both nodes finalized same signed block");
      await pause(250);
    }
    const block = await rpc(node, "eth_getBlockByNumber", [
      receipt.blockNumber,
      false,
    ]);
    assert.ok(block.transactions.includes(hash));
    await transactions(node, receipt.blockNumber, block);
    await transactions(node, firstBlock.number, firstBlock);
  }
  result.after = await state(observer);
  assert.deepEqual(await state(producer), result.after);
  assert.equal(
    BigInt(result.after.recipientBalance),
    BigInt(result.before.recipientBalance) + 29n,
  );
  assert.equal(BigInt(result.after.nonce), BigInt(result.before.nonce) + 1n);
  result.receipt = receipt;
  await stop("observer");
  const reopened = await start("reopened", observerDir, observerKey);
  assert.deepEqual(await state(reopened), result.after);
  assert.deepEqual(
    await rpc(reopened, "eth_getTransactionReceipt", [hash]),
    receipt,
  );
  const newBlock = await rpc(reopened, "eth_getBlockByNumber", [
    receipt.blockNumber,
    false,
  ]);
  await transactions(reopened, receipt.blockNumber, newBlock);
  await transactions(reopened, firstBlock.number, firstBlock);
  result.passed = true;
} catch (error) {
  result.error = String(error);
  process.exitCode = 1;
} finally {
  for (const name of [...nodes.keys()]) await stop(name);
  result.nodesStopped = nodes.size === 0;
  result.endedAt = new Date().toISOString();
  await save();
  signer?.dispose();
  console.log(`Acceptance report: ${join(out, "runtime.json")}`);
}
