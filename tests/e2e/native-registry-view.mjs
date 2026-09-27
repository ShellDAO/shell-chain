#!/usr/bin/env node
// Native Registry view acceptance with independent producer and follower nodes.
// Run instructions and version requirements: docs/ACCOUNT_ABSTRACTION_GUIDE.md.
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, mkdir } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { spawn, spawnSync } from "node:child_process";

assert.ok(
  process.env.SHELL_SDK_ENTRY,
  "Set SHELL_SDK_ENTRY to a compatible built SDK dist/index.js",
);
const {
  createShellProvider,
  decryptKeystore,
  ShellSigner,
  MlDsa65Adapter,
  buildTransaction,
  buildBatchTransaction,
  buildInnerCall,
  validatorRegistryAddress,
} = await import(pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)).href);
const binary = resolve(
  process.env.NODE_BIN ??
    fileURLToPath(new URL("../../target/debug/shell-node", import.meta.url)),
);
const out = await mkdtemp(join(tmpdir(), "shell-native-registry-view-"));
const keyPath = join(out, "validator.json"),
  passwordPath = join(out, "password.txt");
const password = randomBytes(24).toString("hex");
await writeFile(passwordPath, password, { mode: 0o600 });
const generated = spawnSync(
  binary,
  [
    "--password-file",
    passwordPath,
    "key",
    "generate",
    "--algorithm",
    "mldsa65",
    "--output",
    keyPath,
  ],
  { encoding: "utf8" },
);
if (generated.status !== 0) {
  throw Error(generated.stderr || "validator generation failed");
}
const miner = await decryptKeystore(
  JSON.parse(await readFile(keyPath, "utf8")),
  password,
);
async function unusedPort() {
  const listener = createServer();
  await new Promise((done, fail) => {
    listener.once("error", fail);
    listener.listen(0, "127.0.0.1", done);
  });
  const port = listener.address().port;
  await new Promise((done) => listener.close(done));
  return port;
}
const ports = [await unusedPort(), await unusedPort()];
assert.notEqual(ports[0], ports[1]);
const outsider = new ShellSigner("MlDsa65", MlDsa65Adapter.generate());
const signers = [miner, outsider];
const providers = ports.map((port) =>
  createShellProvider({ rpcHttpUrl: `http://127.0.0.1:${port}` }),
);
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
let queue = Promise.resolve();
function paced(request) {
  const task = queue.then(() => pause(100)).then(request);
  queue = task.catch(() => {});
  return task;
}
const rpc = (i, method, params = []) =>
  paced(() => providers[i].client.request({ method, params }));
const nodes = [];
let height = 0;
const result = {
  startedAt: new Date().toISOString(),
  transactions: [],
  versions: {
    node: process.version,
    sdk: JSON.parse(
      await readFile(
        new URL(
          "../package.json",
          pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)),
        ),
        "utf8",
      ),
    ).version,
    binary: spawnSync(binary, ["--version"], {
      encoding: "utf8",
    }).stdout?.trim(),
  },
  adaptations: [
    "Compatible source SDK with transaction wire format v2 is required; this does not prove public npm availability.",
    "Two isolated CLI/RocksDB nodes, loopback libp2p, one ML-DSA authority and one non-authority follower; normal block production and finality.",
    "Native Registry view activates locally at block 3; native AA schedules at genesis. No production activation or multiple-authority quorum claim.",
  ],
};
async function save() {
  await writeFile(join(out, "runtime.json"), JSON.stringify(result, null, 2));
}
async function stop(i) {
  const child = nodes[i];
  if (!child) return;
  const running = () => child.exitCode === null && child.signalCode === null;
  if (running()) child.kill("SIGTERM");
  for (let k = 0; k < 80 && running(); k++) await pause(250);
  if (running()) {
    child.kill("SIGKILL");
    await new Promise((done) => child.once("exit", done));
  }
  assert.ok(!running());
  nodes[i] = undefined;
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    Promise.all([stop(0), stop(1)]).finally(() =>
      process.exit(signal === "SIGINT" ? 130 : 143),
    );
  });
async function start(i, data, key, label, bootnode) {
  const args = [
    "run",
    "--datadir",
    data,
    "--keystore",
    key,
    "--password-file",
    passwordPath,
    "--rpc-addr",
    `127.0.0.1:${ports[i]}`,
    "--metrics-addr",
    "127.0.0.1:0",
    "--block-time",
    "2000",
    "--max-idle-interval",
    "1209600000",
    "--network",
    "dev",
    "--consensus-engine",
    "wpoa",
    "--chain-id",
    "1337",
    "--db",
    "rocksdb",
    "--rpc-api",
    "eth,net,web3,shell,debug,trace",
    "--storage-profile",
    "full",
    "--p2p",
    "--p2p-addr",
    "127.0.0.1:0",
    "--log-level",
    "info",
  ];
  if (bootnode) args.push("--bootnode", bootnode);
  const fd = openSync(join(out, label + "-node.log"), "w");
  const child = spawn(binary, args, { stdio: ["ignore", fd, fd] });
  closeSync(fd);
  nodes[i] = child;
  let spawnError;
  child.once("error", (error) => {
    spawnError = error;
  });
  for (let k = 0; k < 160; k++) {
    if (spawnError) throw spawnError;
    assert.equal(child.exitCode, null, "node exited");
    assert.equal(child.signalCode, null, "node signaled");
    try {
      await rpc(i, "eth_blockNumber");
      return;
    } catch {
      await pause(250);
    }
  }
  throw Error("startup timeout " + label);
}
async function peerReady() {
  for (let k = 0; k < 80; k++) {
    if (
      BigInt(await rpc(0, "net_peerCount")) > 0n &&
      BigInt(await rpc(1, "net_peerCount")) > 0n
    )
      return;
    await pause(300);
  }
  throw Error("peering timeout");
}
async function state(i) {
  const validator = await rpc(i, "shell_getValidatorStatus", [
    miner.getAddress(),
  ]);
  const consensus = await rpc(i, "shell_consensusInfo");
  assert.equal(consensus.validators.length, 1);
  assert.equal(
    consensus.validators[0].weight,
    validator.weight,
    "consensus weight follows registry",
  );
  return {
    validator,
    consensusValidators: consensus.validators,
    algorithms: await rpc(i, "shell_getAlgorithmRegistry"),
    outsiderBalance: await rpc(i, "eth_getBalance", [
      outsider.getAddress(),
      "latest",
    ]),
    outsiderNonce: await rpc(i, "eth_getTransactionCount", [
      outsider.getAddress(),
      "latest",
    ]),
    minerBalance: await rpc(i, "eth_getBalance", [
      miner.getAddress(),
      "latest",
    ]),
    minerNonce: await rpc(i, "eth_getTransactionCount", [
      miner.getAddress(),
      "latest",
    ]),
  };
}
async function compare(hash) {
  for (let k = 0; k < 100; k++) {
    if (Number(BigInt(await rpc(1, "eth_blockNumber"))) === height) break;
    await pause(300);
  }
  const blocks = await Promise.all(
    [0, 1].map((i) => rpc(i, "eth_getBlockByNumber", ["latest", false])),
  );
  assert.equal(Number(BigInt(blocks[1].number)), height);
  assert.equal(blocks[1].hash, blocks[0].hash);
  assert.equal(blocks[1].stateRoot, blocks[0].stateRoot);
  const receipts = await Promise.all(
    [0, 1].map((i) => rpc(i, "eth_getTransactionReceipt", [hash])),
  );
  assert.deepEqual(receipts[1], receipts[0]);
  const states = await Promise.all([0, 1].map(state));
  assert.deepEqual(states[1], states[0]);
  for (let i = 0; i < 2; i++) {
    let finalized;
    for (let k = 0; k < 80; k++) {
      finalized = await rpc(i, "eth_getBlockByNumber", ["finalized", false]);
      if (finalized?.hash === blocks[0].hash) break;
      await pause(250);
    }
    assert.equal(finalized?.hash, blocks[0].hash, "finality");
  }
  return {
    height,
    blockHash: blocks[0].hash,
    stateRoot: blocks[0].stateRoot,
    state: states[0],
  };
}
assert.ok(
  process.env.SOLC_ENTRY,
  "Set SOLC_ENTRY to a solc package entry (0.8.35 tested)",
);
const { default: solc } = await import(
  pathToFileURL(resolve(process.env.SOLC_ENTRY)).href
);
const source = await readFile(
  new URL("./fixtures/native-registry-view.sol", import.meta.url),
  "utf8",
);
const compiled = JSON.parse(
  solc.compile(
    JSON.stringify({
      language: "Solidity",
      sources: { "ValidatorCheck.sol": { content: source } },
      settings: {
        evmVersion: "cancun",
        outputSelection: {
          "*": { "*": ["evm.bytecode.object", "evm.methodIdentifiers"] },
        },
      },
    }),
  ),
);
assert.ok(
  !(compiled.errors ?? []).some((error) => error.severity === "error"),
  JSON.stringify(compiled.errors),
);
const artifact = compiled.contracts["ValidatorCheck.sol"].ValidatorCheck;
result.versions.solc = solc.version();
const view = "0x" + "0".repeat(55) + "100000001";
const word = (n) => BigInt(n).toString(16).padStart(64, "0");
const getValidators = "0xb7ab4db5";
const nonce = async (signer) =>
  Number(
    BigInt(
      await rpc(0, "eth_getTransactionCount", [signer.getAddress(), "latest"]),
    ),
  );
async function confirmed(
  label,
  signer,
  to,
  data,
  status = "0x1",
  aa = false,
  sync = true,
  value = 0n,
) {
  const currentNonce = await nonce(signer);
  const batch = aa
    ? buildBatchTransaction({
        chainId: 1337,
        nonce: currentNonce,
        innerCalls: [buildInnerCall(to, data, 500000, value)],
        gasLimit: 3000000,
      })
    : null;
  const tx =
    batch?.tx ??
    buildTransaction({
      chainId: 1337,
      nonce: currentNonce,
      to,
      value,
      data,
      gasLimit: 3000000,
    });
  const signed = await signer.buildSignedTransaction({
    tx,
    ...(batch ? { aaBundle: batch.aa_bundle } : {}),
    includePublicKey: true,
  });
  const hash = await paced(() => providers[0].sendTransaction(signed));
  let receipt;
  for (let k = 0; k < 120; k++) {
    receipt = await rpc(0, "eth_getTransactionReceipt", [hash]);
    if (receipt) break;
    await pause(250);
  }
  assert.equal(receipt?.status, status, label);
  height++;
  assert.equal(Number(BigInt(receipt.blockNumber)), height);
  assert.equal(await nonce(signer), currentNonce + 1);
  const trace = await rpc(0, "debug_traceTransaction", [
    hash,
    { tracer: "callTracer" },
  ]);
  const entry = { label, hash, receipt, trace };
  result.transactions.push(entry);
  if (sync) entry.synchronization = await compare(hash);
  await save();
  return entry;
}
try {
  const dirs = [join(out, "leader"), join(out, "follower")];
  for (const dir of dirs) await mkdir(dir);
  const followerKey = join(out, "follower-key.json");
  const keyResult = spawnSync(
    binary,
    [
      "--password-file",
      passwordPath,
      "key",
      "generate",
      "--algorithm",
      "mldsa65",
      "--output",
      followerKey,
    ],
    { encoding: "utf8" },
  );
  assert.equal(keyResult.status, 0, keyResult.stderr);
  const genesis = {
    chain_id: 1337,
    chain_name: "native-aa-registry-acceptance",
    network_type: "Dev",
    timestamp: Math.floor(Date.now() / 1000) - 120,
    gas_limit: 30000000,
    extra_data: "native-aa-registry-acceptance",
    alloc: {},
    boot_nodes: [],
    registered_key_algorithm_height: 0,
    aa_account_manager_height: 0,
    aa_validator_registry_height: 0,
    native_registry_view_height: 3,
    fee_accounting_activation_height: 0,
    consensus: {
      engine: "wpoa",
      authorities: [miner.getAddress()],
      authority_pubkeys: [
        "0x" + Buffer.from(miner.getPublicKey()).toString("hex"),
      ],
      weights: [1],
      stakes: [],
      block_time_secs: 2,
      max_future_secs: 300,
      epoch_length: 0,
    },
  };
  for (const signer of signers)
    genesis.alloc[signer.getAddress()] = {
      balance: "0x3635c9adc5dea00000",
      nonce: 0,
      code: null,
      storage: null,
    };
  for (const dir of dirs)
    await writeFile(
      join(dir, "genesis.json"),
      JSON.stringify(genesis, null, 2),
    );
  await start(0, dirs[0], keyPath, "leader");
  let bootnode;
  for (let k = 0; k < 80; k++) {
    bootnode = (await readFile(join(out, "leader-node.log"), "utf8")).match(
      /Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[a-zA-Z0-9]+)/,
    )?.[1];
    if (bootnode) break;
    await pause(250);
  }
  assert.ok(bootnode, "leader complete multiaddr");
  await start(1, dirs[1], followerKey, "follower", bootnode);
  await peerReady();
  const expected = "0x" + word(32) + word(1) + miner.getAddress().slice(2);
  const deployment = await confirmed(
    "deploy complete-address Registry view wrapper",
    miner,
    null,
    "0x" + artifact.evm.bytecode.object,
  );
  const contract = deployment.receipt.contractAddress;
  assert.ok(contract);
  const read = "0x" + artifact.evm.methodIdentifiers["currentValidators()"];
  const membership = (account) =>
    "0x" +
    artifact.evm.methodIdentifiers["isActiveValidator(bytes32)"] +
    account.slice(2);
  await confirmed(
    "wrapper read before activation rejects absent view",
    miner,
    contract,
    read,
    "0x0",
  );
  const active = await confirmed(
    "wrapper read at activation returns full validators",
    miner,
    contract,
    read,
  );
  assert.equal(active.trace.output, expected);
  const member = await confirmed(
    "complete validator address recognized",
    miner,
    contract,
    membership(miner.getAddress()),
  );
  assert.equal(member.trace.output, "0x" + word(1));
  const other = await confirmed(
    "non-validator rejected by membership query",
    outsider,
    contract,
    membership(outsider.getAddress()),
  );
  assert.equal(other.trace.output, "0x" + word(0));
  const truncated = "0x" + "0".repeat(24) + miner.getAddress().slice(-40);
  assert.notEqual(truncated, miner.getAddress());
  const wrong = await confirmed(
    "truncated validator address is not accepted",
    miner,
    contract,
    membership(truncated),
  );
  assert.equal(wrong.trace.output, "0x" + word(0));
  const aa = await confirmed(
    "AA invokes wrapper Registry view",
    outsider,
    contract,
    read,
    "0x1",
    true,
  );
  assert.equal(aa.trace.calls[0].output, expected);
  await confirmed(
    "Registry view rejects native write method",
    miner,
    view,
    "0xa6d5d626" + miner.getAddress().slice(2) + word(2),
    "0x0",
  );
  assert.equal((await state(0)).validator.weight, 1);
  await confirmed(
    "Registry view rejects value",
    miner,
    view,
    getValidators,
    "0x0",
    false,
    true,
    1n,
  );
  for (let i = 0; i < 2; i++)
    assert.equal(BigInt(await rpc(i, "eth_getBalance", [view, "latest"])), 0n);
  await confirmed(
    "Registry view rejects trailing calldata",
    miner,
    view,
    getValidators + "00",
    "0x0",
  );
  const direct = await confirmed(
    "existing native direct read unchanged",
    miner,
    validatorRegistryAddress,
    getValidators,
  );
  assert.equal(direct.trace.output, expected);
  // Observe the existing crypto precompile through a raw STATICCALL relay.
  const runtime = "3660006000376000600036600060015afa503d600060003e3d6000f3";
  const size = (runtime.length / 2).toString(16).padStart(2, "0");
  const relay = await confirmed(
    "deploy original PQ precompile relay",
    miner,
    null,
    "0x60" + size + "600c60003960" + size + "6000f3" + runtime,
  );
  const message = Buffer.from("registry-view-crypto-compatibility"),
    pk = Buffer.from(miner.getPublicKey());
  const signature = Buffer.from(await miner.sign(message));
  const length = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  const payload = Buffer.concat([
    length(pk.length),
    pk,
    length(message.length),
    message,
    signature,
  ]);
  const verified = await confirmed(
    "existing ML-DSA precompile still verifies",
    miner,
    relay.receipt.contractAddress,
    "0x" + payload.toString("hex"),
  );
  assert.equal(verified.trace.output, "0x" + word(1));
  payload[payload.length - 1] ^= 1;
  const invalid = await confirmed(
    "existing ML-DSA precompile rejects tampered signature",
    miner,
    relay.receipt.contractAddress,
    "0x" + payload.toString("hex"),
  );
  assert.equal(invalid.trace.output, "0x" + word(0));
  await confirmed(
    "native governance remains on original address",
    miner,
    validatorRegistryAddress,
    "0xa6d5d626" + miner.getAddress().slice(2) + word(2),
  );
  assert.equal((await state(0)).validator.weight, 2);
  for (const entry of result.transactions) {
    for (let i = 0; i < 2; i++) {
      const current = await state(i);
      assert.deepEqual(
        await rpc(i, "debug_traceTransaction", [
          entry.hash,
          { tracer: "callTracer" },
        ]),
        entry.trace,
        entry.label,
      );
      assert.deepEqual(
        await state(i),
        current,
        "history cannot write live state",
      );
    }
  }
  result.historicalReplayVerified = true;
  await stop(1);
  const offline = await confirmed(
    "Registry view while follower offline",
    miner,
    contract,
    read,
    "0x1",
    false,
    false,
  );
  assert.equal(offline.trace.output, expected);
  await start(1, dirs[1], followerKey, "follower-restart", bootnode);
  await peerReady();
  result.catchupAfterRestart = await compare(offline.hash);
  assert.deepEqual(
    await rpc(1, "debug_traceTransaction", [
      active.hash,
      { tracer: "callTracer" },
    ]),
    active.trace,
  );
  result.finalHeight = height;
  result.passed = true;
} catch (error) {
  result.error = String(error);
  throw error;
} finally {
  await stop(1);
  await stop(0);
  result.nodesStopped = nodes.every((x) => !x);
  result.endedAt = new Date().toISOString();
  await save();
  for (const signer of signers) signer.dispose();
  console.log(`Acceptance report: ${join(out, "runtime.json")}`);
}
