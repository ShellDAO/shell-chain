#!/usr/bin/env node
// Signed native Registry AA acceptance with independent producer and follower nodes.
// Run instructions and version requirements: docs/ACCOUNT_ABSTRACTION_GUIDE.md.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile, writeFile, mkdtemp, mkdir, cp } from "node:fs/promises";
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
  buildContractPaymasterTransaction,
  buildInnerCall,
  accountManagerAddress,
  validatorRegistryAddress,
  encodeSetGuardiansCalldata,
  encodeSubmitRecoveryCalldata,
} = await import(pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)).href);
const binary = resolve(
  process.env.NODE_BIN ??
    fileURLToPath(new URL("../../target/debug/shell-node", import.meta.url)),
);
const quorumRecoveryScenario = process.argv.includes("--quorum-recovery");
const sameHeightForkScenario = process.argv.includes("--fork-sync-same-height");
const weightedForkScenario = process.argv.includes("--fork-sync-weighted") || sameHeightForkScenario;
const forkSyncScenario = process.argv.includes("--fork-sync") || weightedForkScenario;
const twoAuthorities = quorumRecoveryScenario || forkSyncScenario;
const sphincsSignersScenario = process.argv.includes("--block-signers-sphincs");
const blockSignersScenario =
  process.argv.includes("--block-signers") || sphincsSignersScenario;
const syncStatusScenario = process.argv.includes("--sync-status");
const compiledPaymasterScenario = process.argv.includes("--compiled-paymaster");
const contractPaymasterFailureScenario = process.argv.includes("--contract-paymaster-failure");
const contractPaymasterScenario = process.argv.includes("--contract-paymaster") || contractPaymasterFailureScenario || compiledPaymasterScenario;
if (contractPaymasterScenario)
  assert.ok(process.argv.slice(2).every((arg) => arg === (compiledPaymasterScenario ? "--compiled-paymaster" : contractPaymasterFailureScenario ? "--contract-paymaster-failure" : "--contract-paymaster")),
    "Run each contract-paymaster scenario separately");
const out = await mkdtemp(join(tmpdir(), "shell-native-aa-registry-"));
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
    sphincsSignersScenario || (twoAuthorities && !sameHeightForkScenario) ? "slhdsa" : "mldsa65",
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
const metricsPorts = syncStatusScenario ? [await unusedPort(), await unusedPort()] : [];
const outsider = new ShellSigner("MlDsa65", MlDsa65Adapter.generate());
const signers = [miner, outsider];
const prunedEpochScenario = process.argv.includes("--epoch-pruned-restart");
const pruneFollower = prunedEpochScenario || blockSignersScenario;
const epochScenario = process.argv.includes("--epoch-restart") || prunedEpochScenario;
let expectedConsensusWeight = 1;
let expectedMembers = [miner.getAddress()];
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
const nodeLogLabels = [];
let height = 0;
const result = {
  startedAt: new Date().toISOString(),
  scenario: sameHeightForkScenario ? "fork-sync-same-height" : weightedForkScenario ? "fork-sync-weighted" : forkSyncScenario ? "fork-sync" : quorumRecoveryScenario ? "quorum-recovery" : blockSignersScenario ? "block-signers" : syncStatusScenario ? "live-sync-status" : prunedEpochScenario ? "epoch-pruned-restart" : epochScenario ? "epoch-restart" : "native-aa-events",
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
    sameHeightForkScenario
      ? "Two isolated full RocksDB ML-DSA authority nodes with unequal weights and loopback libp2p. Mixed-algorithm recovery is covered separately."
      : twoAuthorities
      ? "Two isolated full RocksDB authority nodes, loopback libp2p, SLH-DSA-SHA2-256f and ML-DSA keys."
      : `Two isolated CLI/RocksDB nodes, loopback libp2p, one ${sphincsSignersScenario ? "SLH-DSA-SHA2-256f" : "ML-DSA"} authority and one non-authority follower; normal block production and finality.`,
    "AA ValidatorRegistry activates locally at block 3, AccountManager at genesis. No production activation, multiple-authority quorum or algorithm migration claim.",
  ],
};
if (pruneFollower)
  result.adaptations.push(
    "Full producer and light follower with one-block state/body retention; this scaled experiment does not establish the default 4096-block retention window.",
  );
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
  if (contractPaymasterScenario) {
    const command = result.nativeCommands?.find((entry) => entry.pid === child.pid);
    if (command) Object.assign(command, { endedAt: new Date().toISOString(), exitCode: child.exitCode, signal: child.signalCode });
    await save();
  }
  nodes[i] = undefined;
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    Promise.all(nodes.map((_, index) => stop(index))).finally(() =>
      process.exit(signal === "SIGINT" ? 130 : 143),
    );
  });
async function start(i, data, key, label, bootnode, waitForRpc = true) {
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
    syncStatusScenario ? `127.0.0.1:${metricsPorts[i]}` : "127.0.0.1:0",
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
    pruneFollower && i === 1 ? "light" : "full",
    "--p2p",
    "--p2p-addr",
    "127.0.0.1:0",
    "--log-level",
    "info",
  ];
  if (pruneFollower && i === 1)
    args.push("--pruning", "1", "--body-retention", "1");
  if (bootnode) args.push("--bootnode", bootnode);
  const fd = openSync(join(out, label + "-node.log"), "w");
  const startedAt = new Date().toISOString();
  const child = spawn(binary, args, { stdio: ["ignore", fd, fd] });
  closeSync(fd);
  nodes[i] = child;
  nodeLogLabels[i] = label;
  let spawnError;
  child.once("error", (error) => {
    spawnError = error;
  });
  if (contractPaymasterScenario) {
    (result.nativeCommands ??= []).push({ args: [binary, ...args], pid: child.pid, startedAt });
    await save();
  }
  if (!waitForRpc) return;
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
  assert.deepEqual(
    consensus.validators.map((v) => v.address.toLowerCase()).sort(),
    expectedMembers.map((address) => address.toLowerCase()).sort(),
    "consensus membership follows committed governance",
  );
  assert.equal(
    consensus.validators.find(
      (v) => v.address.toLowerCase() === miner.getAddress().toLowerCase(),
    ).weight,
    epochScenario ? expectedConsensusWeight : validator.weight,
    "consensus weight follows the last activated Registry state",
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
  // The configured single authority produces every non-genesis block. Check
  // the same durable activity on the independently importing/pruned follower.
  const validatorVotes = await Promise.all([0, 1].map((i) => rpc(i, "shell_getValidatorVotes")));
  assert.deepEqual(validatorVotes[1], validatorVotes[0]);
  assert.equal(validatorVotes[0].blockHash, blocks[0].hash);
  assert.equal(validatorVotes[0].toBlock, blocks[0].number);
  assert.equal(validatorVotes[0].fromBlock, "0x" + Math.max(1, height - 199).toString(16));
  assert.equal(validatorVotes[0].window, 200);
  assert.deepEqual(validatorVotes[0].validators, expectedMembers.map((address) => ({
    address,
    blocksProduced: address === miner.getAddress() ? Math.min(height, 200) : 0,
    lastBlockProduced: address === miner.getAddress() ? blocks[0].number : null,
    uptime: null,
  })).sort((a, b) => a.address.localeCompare(b.address)));
  for (let i = 0; i < 2; i++) {
    assert.deepEqual(await state(i), states[i], "activity reads preserve state");
  }
  let epochInfo;
  if (epochScenario) {
    const previous = await rpc(0, "eth_getBlockByNumber", [
      "0x" + Math.max(0, height - 10).toString(16),
      false,
    ]);
    const expected = {
      currentEpoch: Math.floor(height / 5),
      epochLength: 5,
      blocksInEpoch: height % 5,
      currentBlockTime:
        (Number(BigInt(blocks[0].timestamp)) -
          Number(BigInt(previous.timestamp))) /
        Math.min(height, 10),
      activeValidators: expectedMembers.length,
    };
    epochInfo = await Promise.all([0, 1].map((i) => rpc(i, "shell_getEpochInfo")));
    for (let i = 0; i < 2; i++) {
      assert.deepEqual(epochInfo[i], expected, "canonical epoch and active set");
      assert.deepEqual(await state(i), states[i], "epoch reads preserve state");
      assert.deepEqual(
        await rpc(i, "eth_getBlockByNumber", ["latest", false]),
        blocks[i],
        "epoch reads preserve the canonical head",
      );
    }
  }
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
    validatorVotes,
    ...(epochInfo ? { epochInfo } : {}),
  };
}
const nonce = async (signer) =>
  Number(
    BigInt(
      await rpc(0, "eth_getTransactionCount", [signer.getAddress(), "latest"]),
    ),
  );
const native = (data, gas = 200000, value = 0n) =>
  buildInnerCall(validatorRegistryAddress, data, gas, value);
const word = (value) => BigInt(value).toString(16).padStart(64, "0");
const getValidators = "0xb7ab4db5";
const weight = (n) => "0xa6d5d626" + miner.getAddress().slice(2) + word(n);
const deprecate = "0xa4b88278" + word(2);
const bad = native("0xffffffff");
async function confirmed(
  label,
  signer,
  calls,
  status = "0x1",
  sync = true,
  direct = false,
) {
  const currentNonce = await nonce(signer);
  const balanceBefore = BigInt(
    await rpc(0, "eth_getBalance", [signer.getAddress(), "latest"]),
  );
  const batch = direct
    ? null
    : buildBatchTransaction({
        chainId: 1337,
        nonce: currentNonce,
        innerCalls: calls,
        gasLimit: 3000000,
      });
  const tx = direct
    ? buildTransaction({
        chainId: 1337,
        nonce: currentNonce,
        to: validatorRegistryAddress,
        value: 0n,
        data: calls[0]?.data ?? getValidators,
        gasLimit: 3000000,
      })
    : batch.tx;
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
  if (signer === outsider) {
    const balanceAfter = BigInt(
      await rpc(0, "eth_getBalance", [signer.getAddress(), "latest"]),
    );
    assert.equal(
      balanceBefore - balanceAfter,
      BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice),
      "exact outer fee on success and failure",
    );
  }
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
async function runContractPaymasterScenario() {
  assert.equal(typeof buildContractPaymasterTransaction, "function");
  const failure = contractPaymasterFailureScenario;
  const compiled = compiledPaymasterScenario;
  result.scenario = compiled ? "compiled-native-paymaster" : failure ? "signed-contract-paymaster-failure" : "signed-contract-paymaster";
  result.adaptations = [
    `${compiled ? "Independent producer and observer" : "One producer"} on isolated full RocksDB with ML-DSA; fresh ${failure ? "11-wei" : "unfunded"} sender and funded contract paymaster.`,
    "Fee accounting activates at this temporary genesis only; no live network activation.",
    compiled
      ? "Compiled PQABI policy and native address context activate at this isolated genesis only; no deployment or live activation."
      : "Genesis EVM policy/storage fixtures test execution, not contract deployment or native-address activation.",
  ];
  const data = join(out, "contract-paymaster");
  await mkdir(data);
  const paymaster = "0x" + (compiled ? "a1" : "00").repeat(12) + "91".repeat(20);
  const target = "0x" + (compiled ? "a2" : "00").repeat(12) + "92".repeat(20);
  const revert = "0x" + "00".repeat(12) + "93".repeat(20);
  const sender = outsider.getAddress();
  const word = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");
  // ABI argument 4 holds the context offset. Approve only a first byte of 0xab.
  const fixture = compiled ? JSON.parse(await readFile(new URL(
    "../../crates/pqvm/tests/fixtures/native-paymaster-identity.json", import.meta.url), "utf8")) : null;
  const policyCode = fixture?.artifacts.pqvm.deployedBytecode ?? "0x6064356004016020013560001a60ab1460005260206000f3";
  const genesis = {
    chain_id: 1337,
    chain_name: "contract-paymaster-acceptance",
    network_type: "Dev",
    timestamp: Math.floor(Date.now() / 1000) - 120,
    gas_limit: 30000000,
    extra_data: "contract-paymaster-acceptance",
    fee_accounting_activation_height: 0,
    ...(compiled ? { native_address_context_height: 0 } : {}),
    alloc: {
      [paymaster]: { balance: "0x3635c9adc5dea00000", nonce: 0, code: policyCode, storage: compiled ? { [word(0)]: sender } : {} },
      [target]: { balance: "0x0", nonce: 0, code: "0x60003560005500", storage: {} },
    },
    boot_nodes: [],
    consensus: {
      engine: "wpoa", authorities: [miner.getAddress()],
      authority_pubkeys: ["0x" + Buffer.from(miner.getPublicKey()).toString("hex")],
      weights: [1], stakes: [], block_time_secs: 2, max_future_secs: 300, epoch_length: 0,
    },
  };
  if (failure) {
    genesis.alloc[sender] = { balance: "0xb", nonce: 0, code: null, storage: {} };
    genesis.alloc[target].code = "0x60003560005560006000a000";
    genesis.alloc[revert] = { balance: "0x0", nonce: 0, code: "0x60006000fd", storage: {} };
  }
  await writeFile(join(data, "genesis.json"), JSON.stringify(genesis, null, 2));
  const snapshot = async (i = 0) => ({
    head: await rpc(i, "eth_getBlockByNumber", ["latest", false]),
    senderBalance: await rpc(i, "eth_getBalance", [sender, "latest"]),
    payerBalance: await rpc(i, "eth_getBalance", [paymaster, "latest"]),
    senderNonce: await rpc(i, "eth_getTransactionCount", [sender, "latest"]),
    payerNonce: await rpc(i, "eth_getTransactionCount", [paymaster, "latest"]),
    slot: await rpc(i, "eth_getStorageAt", [target, "0x0", "latest"]),
    policySlot: await rpc(i, "eth_getStorageAt", [paymaster, "0x0", "latest"]),
    pending: await rpc(i, "shell_pendingCount"),
    ...(failure ? {
      targetBalance: await rpc(i, "eth_getBalance", [target, "latest"]),
      registeredKey: await rpc(i, "shell_getPqPubkey", [sender]),
    } : {}),
  });
  const innerCalls = failure
    ? [{ to: target, value: "0x7", data: word(31), gas_limit: "0xc350" },
      { to: revert, value: "0x0", data: "0x", gas_limit: "0xc350" }]
    : [{ to: target, value: "0x0", data: word(23), gas_limit: "0xc350" }];
  const signed = async (context, maxFeePerGas = 1000000000000, actor = outsider) => {
    const { tx, aa_bundle } = buildContractPaymasterTransaction({
      chainId: 1337, nonce: 0,
      innerCalls,
      gasLimit: 300000, maxFeePerGas, maxPriorityFeePerGas: 0,
      paymaster, paymasterContext: [context],
    });
    assert.equal(aa_bundle.paymaster_signature, null);
    return actor.buildSignedTransaction({ tx, aaBundle: aa_bundle, includePublicKey: true });
  };
  await start(0, data, keyPath, "contract-paymaster");
  let follower;
  if (compiled) {
    const directory = join(out, "compiled-follower"), key = join(out, "compiled-follower-key.json");
    await mkdir(directory);
    await writeFile(join(directory, "genesis.json"), JSON.stringify(genesis, null, 2));
    const generated = spawnSync(binary, ["--password-file", passwordPath, "key", "generate", "--algorithm", "mldsa65", "--output", key], { encoding: "utf8" });
    assert.equal(generated.status, 0, generated.stderr);
    const bootnode = (await readFile(join(out, "contract-paymaster-node.log"), "utf8")).match(
      /Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[a-zA-Z0-9]+)/)?.[1];
    assert.ok(bootnode, "producer complete multiaddr");
    await start(1, directory, key, "compiled-follower", bootnode);
    await peerReady();
    follower = { directory, key, child: nodes[1] };
  }
  const before = await snapshot();
  assert.equal(before.senderBalance, failure ? "0xb" : "0x0");
  if (!failure) {
    const { toRlp } = createRequire(resolve(process.env.SHELL_SDK_ENTRY))("viem");
    const simulationInput = {
      paymaster, sender,
      inner_calls_data: toRlp([[target, "0x", word(23), "0xc350"]]),
      gas_limit: "0x493e0", max_fee_per_gas: "0xe8d4a51000", paymaster_context: "0xab",
    };
    result.paymasterSimulation = await rpc(0, "shell_estimatePaymasterGas", [simulationInput]);
    if (compiled) {
      result.compiledPolicy = { compiler: fixture.compiler, sdk: fixture.sdk };
      const alias = "0x" + (sender.slice(2, 26) === "56".repeat(12) ? "57" : "56").repeat(12) + sender.slice(26);
      result.compiledRejections = [];
      for (const change of [
        { sender: alias }, { max_fee_per_gas: "0xe8d4a51001" }, { paymaster_context: "0xac" },
      ]) {
        const input = { ...simulationInput, ...change };
        await assert.rejects(() => rpc(0, "shell_estimatePaymasterGas", [input]), (error) => {
          result.compiledRejections.push({ method: "shell_estimatePaymasterGas", input, error: error.message });
          return /contract paymaster rejected transaction/.test(error.message);
        });
        assert.deepEqual(await snapshot(), before);
        await save();
      }
      for (const denied of [await signed(0xab, 1000000000001), await signed(0xab, 1000000000000, miner)]) {
        await assert.rejects(() => paced(() => providers[0].sendTransaction(denied)), (error) => {
          result.compiledRejections.push({ method: "shell_sendTransaction", input: denied, error: error.message });
          return /contract paymaster rejected transaction/.test(error.message);
        });
        assert.deepEqual(await snapshot(), before);
        await save();
      }
      result.identityAndCostRejectedWithoutWrites = true;
    }
    assert.equal(result.paymasterSimulation.simulation_status, "simulated");
    assert.equal(result.paymasterSimulation.within_cap, true);
    assert.deepEqual(await snapshot(), before);
    const rejected = await signed(0xac);
    result.rejectedContextBundle = rejected;
    await save();
    await assert.rejects(() => paced(() => providers[0].sendTransaction(rejected)),
      /contract paymaster rejected transaction/);
    assert.deepEqual(await snapshot(), before);
    result.wrongContextRejectedWithoutWrites = true;
  }
  const packet = await signed(0xab);
  result.submittedBundle = packet;
  await save();
  const hash = await paced(() => providers[0].sendTransaction(packet));
  let receipt;
  for (let attempt = 0; attempt < 120; attempt++) {
    receipt = await rpc(0, "eth_getTransactionReceipt", [hash]);
    if (receipt) break;
    await pause(250);
  }
  assert.equal(receipt?.status, failure ? "0x0" : "0x1");
  const after = await snapshot();
  const fee = BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice);
  assert.ok(fee > 0n);
  assert.equal(BigInt(before.payerBalance) - BigInt(after.payerBalance), fee);
  assert.equal(after.senderBalance, before.senderBalance);
  assert.equal(after.senderNonce, "0x1");
  assert.equal(after.payerNonce, before.payerNonce);
  assert.equal(after.slot, failure ? word(0) : word(23));
  assert.equal(after.policySlot, compiled ? sender : word(0));
  const sponsorship = await rpc(0, "shell_isSponsored", [hash]);
  assert.equal(sponsorship.found, true);
  assert.equal(sponsorship.location, "chain");
  assert.equal(sponsorship.is_aa_bundle, true);
  assert.equal(sponsorship.sponsored, true);
  assert.equal(sponsorship.sender, sender);
  assert.equal(sponsorship.paymaster, paymaster);
  assert.equal(sponsorship.inner_call_count, innerCalls.length);
  if (failure) {
    assert.equal(after.targetBalance, "0x0");
    assert.deepEqual(receipt.logs, []);
    assert.deepEqual(await rpc(0, "eth_getLogs", [{
      fromBlock: receipt.blockNumber, toBlock: receipt.blockNumber, address: target,
    }]), []);
    const trace = await rpc(0, "debug_traceTransaction", [hash, { tracer: "callTracer" }]);
    result.failedBatchTrace = trace;
    await save();
    assert.equal(trace.failed, true);
    assert.equal(trace.calls?.length, 2);
    assert.equal(trace.calls[0].to, target);
    assert.ok(!trace.calls[0].error);
    assert.equal(BigInt(trace.calls[0].value), 7n);
    assert.equal(trace.calls[1].to, revert);
    assert.match(trace.calls[1].error, /reverted/);
    assert.ok(trace.structLogs.some((step) => step.op === "SSTORE" && step.storage?.[word(0)] === word(31)));
    assert.ok(trace.structLogs.some((step) => step.op === "LOG0"));
    assert.ok(trace.structLogs.some((step) => step.op === "REVERT"));
    if (after.registeredKey !== null)
      assert.equal(after.registeredKey, "0x" + Buffer.from(outsider.getPublicKey()).toString("hex"));
    assert.deepEqual(await snapshot(), after, "historical trace and logs do not write state");
  }
  assert.ok(BigInt((await rpc(0, "shell_getFinalityInfo")).lastFinalizedBlock) >= BigInt(receipt.blockNumber));
  result.transactions.push({ label: failure ? "contract-sponsored reverted batch" : "contract-sponsored storage call", hash, receipt });
  result.contractSponsorship = { before, after, sponsorship, fee: fee.toString() };
  if (compiled) {
    for (let attempt = 0; attempt < 120; attempt++) {
      if (await rpc(1, "eth_getTransactionReceipt", [hash])) break;
      await pause(250);
    }
    assert.deepEqual(await rpc(1, "eth_getTransactionReceipt", [hash]), receipt);
    assert.deepEqual(await snapshot(1), after, "independent block import agrees on root, fee and full identities");
    result.compiledTrace = await rpc(1, "debug_traceTransaction", [hash, { tracer: "callTracer" }]);
    assert.equal(result.compiledTrace.failed, false);
    assert.deepEqual(await snapshot(1), after, "historical replay is read-only");
    await stop(1);
    assert.equal(follower.child.exitCode, 0);
    await start(1, follower.directory, follower.key, "compiled-follower-restart");
    assert.deepEqual(await snapshot(1), after);
    assert.deepEqual(await rpc(1, "eth_getTransactionReceipt", [hash]), receipt);
    assert.deepEqual(await rpc(1, "debug_traceTransaction", [hash, { tracer: "callTracer" }]), result.compiledTrace);
    result.independentImportAndReopen = true;
    const reopenedFollower = nodes[1];
    await stop(1);
    assert.equal(reopenedFollower.exitCode, 0);
  }
  const child = nodes[0];
  await stop(0);
  assert.equal(child.exitCode, 0);
  await start(0, data, keyPath, "contract-paymaster-restart");
  assert.deepEqual(await snapshot(), after);
  assert.deepEqual(await rpc(0, "eth_getTransactionReceipt", [hash]), receipt);
  assert.deepEqual(await rpc(0, "shell_isSponsored", [hash]), sponsorship);
  if (failure) {
    assert.deepEqual(await rpc(0, "debug_traceTransaction", [hash, { tracer: "callTracer" }]), result.failedBatchTrace);
    assert.deepEqual(await rpc(0, "eth_getLogs", [{
      fromBlock: receipt.blockNumber, toBlock: receipt.blockNumber, address: target,
    }]), []);
    assert.deepEqual(await snapshot(), after);
  }
  const reopened = nodes[0];
  await stop(0);
  assert.equal(reopened.exitCode, 0);
  result.restartPreservedContractSponsorship = true;
  result.nativeExitCodes = result.nativeCommands.map((command) => command.exitCode);
  result.passed = true;
}

async function runScenario() {
  if (contractPaymasterScenario) return runContractPaymasterScenario();
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
  const otherAuthority = twoAuthorities
    ? await decryptKeystore(JSON.parse(await readFile(followerKey, "utf8")), password)
    : null;
  if (otherAuthority) signers.push(otherAuthority);
  const authorities = otherAuthority ? [miner, otherAuthority] : [miner];
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
    aa_validator_registry_height: 3,
    native_validator_events_height: 16,
    bloom_activation_height: 0,
    fee_accounting_activation_height: 0,
    consensus: {
      engine: "wpoa",
      authorities: authorities.map((signer) => signer.getAddress()),
      authority_pubkeys: authorities.map((signer) =>
        "0x" + Buffer.from(signer.getPublicKey()).toString("hex")),
      weights: authorities.map((_, index) => weightedForkScenario && index === 1 ? 3 : 1),
      stakes: [],
      block_time_secs: 2,
      max_future_secs: 300,
      epoch_length: epochScenario ? 5 : 0,
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
  if (syncStatusScenario) {
    // Create the backlog through the existing real signed transaction path.
    for (let block = 1; block <= 21; block++)
      await confirmed(`sync backlog ${block}`, miner, [
        buildInnerCall(outsider.getAddress(), "0x", 100000, 1n),
      ], "0x1", false);
    const producerBlock = await rpc(0, "eth_getBlockByNumber", ["0x15", false]);
    await start(1, dirs[1], followerKey, "follower", bootnode, false);
    let socket;
    const events = [];
    let syncingId, headsId;
    try {
      for (let attempt = 0; attempt < 400; attempt++) {
        try {
          socket = await new Promise((done, fail) => {
            const candidate = new WebSocket(`ws://127.0.0.1:${ports[1]}`);
            candidate.addEventListener("open", () => done(candidate), { once: true });
            candidate.addEventListener("error", () => fail(Error("WS not ready")), { once: true });
          });
          break;
        } catch { await pause(20); }
      }
      assert.ok(socket, "follower WebSocket listening");
      socket.addEventListener("message", ({ data }) => {
        const message = JSON.parse(data);
        events.push(message);
        if (message.id === 1) syncingId = message.result;
        if (message.id === 2) headsId = message.result;
      });
      socket.send(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_subscribe", params: ["syncing"] }));
      socket.send(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "eth_subscribe", params: ["newHeads"] }));
      const samples = [];
      let completeAt;
      const deadline = Date.now() + 60000;
      while (Date.now() < deadline) {
        assert.equal(nodes[1].exitCode, null, "follower exited during catch-up");
        const health = await (await fetch(`http://127.0.0.1:${metricsPorts[1]}/health`,
          { signal: AbortSignal.timeout(3000) })).json();
        const syncing = await providers[1].client.request({ method: "eth_syncing", params: [] });
        const head = await providers[1].client.request({ method: "eth_blockNumber", params: [] });
        samples.push({ health, syncing, head });
        if (head === "0x15" && !health.syncing) {
          completeAt ??= Date.now();
          if (Date.now() - completeAt > 1000) break;
        }
        await pause(25);
      }
      result.syncStatus = { events, samples, producerHash: producerBlock.hash };
      assert.ok(syncingId && headsId, "both subscriptions acknowledged");
      const syncEvents = events.filter((e) => e.params?.subscription === syncingId)
        .map((e) => e.params.result);
      const headEvents = events.filter((e) => e.params?.subscription === headsId);
      assert.ok(headEvents.length > 0, "real imported heads reach the subscription");
      assert.ok(samples.some((s) => s.health.syncing), "actual catch-up observed; otherwise inconclusive");
      assert.ok(samples.some((s) => s.syncing !== false), "HTTP reports actual catch-up");
      const active = syncEvents.filter((e) => e?.syncing === true);
      assert.ok(active.length > 0, "WebSocket reports actual catch-up");
      for (const event of active) {
        const { startingBlock, currentBlock, highestBlock } = event.status;
        for (const value of [startingBlock, currentBlock, highestBlock])
          assert.match(value, /^0x(?:0|[1-9a-f][0-9a-f]*)$/);
        assert.ok(BigInt(startingBlock) <= BigInt(currentBlock));
        assert.ok(BigInt(currentBlock) <= BigInt(highestBlock));
        assert.ok(BigInt(highestBlock) <= 21n, "no fabricated peer target height");
      }
      assert.equal(syncEvents.at(-1), false, "WebSocket reports catch-up completion");
      assert.equal(samples.at(-1).syncing, false, "HTTP reports catch-up completion");
      const importedBlock = await rpc(1, "eth_getBlockByNumber", ["0x15", false]);
      assert.equal(importedBlock.hash, producerBlock.hash, "independently imported canonical block");
      result.finalHeight = height;
    } finally { socket?.close(); }
    await stop(1);
    await start(1, dirs[1], followerKey, "sync-restarted-follower", bootnode);
    await peerReady();
    let idleSamples = 0;
    for (let attempt = 0; attempt < 80 && idleSamples < 5; attempt++) {
      idleSamples = await rpc(1, "eth_syncing") === false ? idleSamples + 1 : 0;
      await pause(100);
    }
    assert.equal(idleSamples, 5, "reopened follower returns to idle");
    const reopenedBlock = await rpc(1, "eth_getBlockByNumber", ["0x15", false]);
    assert.equal(reopenedBlock.hash, producerBlock.hash, "canonical import survives process reopen");
    const reopenedSocket = new WebSocket(`ws://127.0.0.1:${ports[1]}`);
    try {
      await new Promise((done, fail) => {
        reopenedSocket.addEventListener("open", done, { once: true });
        reopenedSocket.addEventListener("error", fail, { once: true });
      });
      const initial = new Promise((done, fail) => {
        const timeout = setTimeout(() => fail(Error("reopened sync status timeout")), 3000);
        reopenedSocket.addEventListener("message", ({ data }) => {
          const message = JSON.parse(data);
          if (message.method === "eth_subscription") {
            clearTimeout(timeout);
            done(message.params.result);
          }
        });
      });
      reopenedSocket.send(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_subscribe", params: ["syncing"] }));
      assert.equal(await initial, false, "reopened subscription starts from actual idle status");
      result.syncStatus.reopenVerified = true;
    } finally { reopenedSocket.close(); }
    result.liveSyncStatusVerified = true;
    result.passed = true;
    return;
  }
  await start(1, dirs[1], followerKey, "follower", bootnode);
  await peerReady();
  if (forkSyncScenario) {
    result.adaptations.push(weightedForkScenario
      ? "Two temporary authorities with weights [1, 3], quorum 3, and two observers. One high-weight authority can finalize alone; one low-weight authority cannot."
      : "Two equal-weight temporary authorities and two non-authority observers; one provisional suffix and a genuine competing quorum-certified branch. This does not establish Byzantine fault tolerance or production activation.");
    const commonHeight = weightedForkScenario ? 3 : 1;
    const branchHeight = commonHeight + 1;
    const tipHeight = branchHeight + 1;
    let finalHeight = tipHeight;
    let transferred = 13;
    const recipient = outsider.getAddress();
    const initialBalance = BigInt(genesis.alloc[recipient].balance);
    const extraDirs = [join(out, "observer"), join(out, "control")];
    const extraKeys = [join(out, "observer-key.json"), join(out, "control-key.json")];
    for (let index = 0; index < 2; index++) {
      ports.push(await unusedPort());
      providers.push(createShellProvider({ rpcHttpUrl: `http://127.0.0.1:${ports[index + 2]}` }));
      await mkdir(extraDirs[index]);
      await writeFile(join(extraDirs[index], "genesis.json"), JSON.stringify(genesis));
      const generated = spawnSync(binary, ["--password-file", passwordPath, "key", "generate", "--algorithm", "mldsa65", "--output", extraKeys[index]], { encoding: "utf8" });
      assert.equal(generated.status, 0, generated.stderr);
    }
    async function address(label) {
      for (let attempt = 0; attempt < 80; attempt++) {
        const value = (await readFile(join(out, label + "-node.log"), "utf8"))
          .match(/Listening on (\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[a-zA-Z0-9]+)/)?.[1];
        if (value) return value;
        await pause(100);
      }
      throw Error("missing native peer address: " + label);
    }
    async function observe(index, expectedHeight, expectedFinality, transferred) {
      const deadline = Date.now() + 90000;
      let last;
      while (Date.now() < deadline) {
        const head = await rpc(index, "eth_getBlockByNumber", ["latest", false]);
        const finalized = await rpc(index, "eth_getBlockByNumber", ["finalized", false]);
        const balance = await rpc(index, "eth_getBalance", [recipient, "latest"]);
        last = { head, finalized, balance };
        if (Number(BigInt(head.number)) === expectedHeight && Number(BigInt(finalized.number)) === expectedFinality) {
          // Separate RPC reads can straddle adoption of a same-height fork.
          // Retry a changed head before combining its hash with newer finality/state.
          const currentHead = await rpc(index, "eth_getBlockByNumber", ["latest", false]);
          if (currentHead.hash !== head.hash) continue;
          assert.equal(BigInt(balance), initialBalance + BigInt(transferred));
          if (weightedForkScenario) {
            const safe = await rpc(index, "eth_getBlockByNumber", ["safe", false]);
            assert.equal(safe.hash, finalized.hash, "safe aliases weighted finality");
          }
          return { head, finalized, balance };
        }
        await pause(100);
      }
      result.forkObservationFailure = { index, expectedHeight, expectedFinality, transferred, last };
      await save();
      throw Error(`fork sync timeout: node ${index}, height ${expectedHeight}, finalized ${expectedFinality}`);
    }
    async function transfer(value, label, index = 0) {
      const senderNonce = Number(BigInt(await rpc(index, "eth_getTransactionCount", [miner.getAddress(), "latest"])));
      const tx = buildTransaction({ chainId: 1337, nonce: senderNonce, to: recipient, value: BigInt(value), gasLimit: 100000 });
      const signed = await miner.buildSignedTransaction({ tx, includePublicKey: true });
      const hash = await paced(() => providers[index].sendTransaction(signed));
      for (let attempt = 0; attempt < 240; attempt++) {
        const receipt = await rpc(index, "eth_getTransactionReceipt", [hash]);
        if (receipt) {
          assert.equal(receipt.status, "0x1");
          result.transactions.push({ label, hash, receipt });
          await save();
          return hash;
        }
        await pause(100);
      }
      throw Error("fork transfer receipt timeout: " + label);
    }
    const commonTx = await transfer(1, "common finalized block");
    const commonTransactions = [commonTx];
    // In the declared [1, 3] WRR order, the low-weight authority proposes at 4.
    // Reach that slot with genuine zero-value transfers before taking its peer offline.
    if (weightedForkScenario) {
      commonTransactions.push(await transfer(0, "common proposer-slot advance 2"));
      commonTransactions.push(await transfer(0, "common proposer-slot advance 3"));
    }
    const common = await observe(0, commonHeight, commonHeight, 1);
    await observe(1, commonHeight, commonHeight, 1);
    await stop(1);
    await stop(0);
    const branchDirs = [join(out, "branch-b-producer"), join(out, "branch-b-authority")];
    await cp(dirs[0], branchDirs[0], { recursive: true });
    await cp(dirs[1], branchDirs[1], { recursive: true });
    await start(0, dirs[0], keyPath, "fork-a-producer");
    await start(2, extraDirs[0], extraKeys[0], "fork-observer", await address("fork-a-producer"));
    await observe(2, commonHeight, commonHeight, 1);
    const orphanTx = await transfer(2, "unfinalized old suffix");
    const provisional = await observe(2, branchHeight, commonHeight, 3);
    await stop(0);
    if (sameHeightForkScenario) {
      // The heavy authority creates a certified competing tip while isolated
      // from the provisional branch. Do not create a higher descendant.
      await start(1, branchDirs[1], followerKey, "fork-b-authority");
    } else {
      await start(0, branchDirs[0], keyPath, "fork-b-producer");
      await start(1, branchDirs[1], followerKey, "fork-b-authority", await address("fork-b-producer"));
      await peerReady();
    }
    const branchBoot = await address(sameHeightForkScenario ? "fork-b-authority" : "fork-b-producer");
    await start(3, extraDirs[1], extraKeys[1], "fork-control", branchBoot);
    await observe(3, commonHeight, commonHeight, 1);
    const branchTx = await transfer(4, "certified competing block", sameHeightForkScenario ? 1 : 0);
    const branchTwo = await observe(sameHeightForkScenario ? 1 : 0, branchHeight, branchHeight, 5);
    assert.notEqual(branchTwo.head.hash, provisional.head.hash);
    let tipTx;
    if (sameHeightForkScenario) {
      finalHeight = branchHeight;
      transferred = 5;
    } else {
      tipTx = await transfer(8, "certified competing descendant");
    }
    let expected = await observe(3, finalHeight, finalHeight, transferred);
    let heavyTx;
    if (weightedForkScenario && !sameHeightForkScenario) {
      // Connect the independent control directly to the authority that remains online.
      await stop(3);
      await start(3, extraDirs[1], extraKeys[1], "weighted-control", await address("fork-b-authority"));
      await stop(0);
      const signed = await miner.buildSignedTransaction({
        tx: buildTransaction({ chainId: 1337, nonce: 5, to: recipient, value: 16n, gasLimit: 100000 }),
        includePublicKey: true,
      });
      heavyTx = await paced(() => providers[1].sendTransaction(signed));
      finalHeight = 6;
      transferred = 29;
      const heavyOnly = await observe(1, finalHeight, finalHeight, transferred);
      result.weightedFinality = { weights: [1, 3], totalWeight: 4, quorum: 3, onlineAuthorityIdentities: 1, heavyOnly };
      await save();
      expected = await observe(3, finalHeight, finalHeight, transferred);
      const receipt = await rpc(1, "eth_getTransactionReceipt", [heavyTx]);
      assert.equal(receipt.status, "0x1");
      result.transactions.push({ label: "one high-weight authority finalizes alone", hash: heavyTx, receipt });
    }
    const signerHeight = weightedForkScenario ? finalHeight : branchHeight;
    const signerTag = "0x" + signerHeight.toString(16);
    const expectedSigners = await rpc(3, "shell_getBlockSigners", [signerTag]);
    const certifiedAuthorities = weightedForkScenario ? [otherAuthority] : authorities;
    assert.deepEqual(expectedSigners.signers, certifiedAuthorities.map((signer) => ({
      address: signer.getAddress(),
      pqPubkey: "0x" + Buffer.from(signer.getPublicKey()).toString("hex"),
      signatureValid: true,
    })).sort((a, b) => a.address.localeCompare(b.address)));
    // Preserve the observer's provisional suffix. Only the already-finalized
    // remote authority restarts to establish the new inbound route.
    await stop(1);
    await start(1, branchDirs[1], followerKey, "fork-bridge", await address("fork-observer"));
    const adopted = await observe(2, finalHeight, finalHeight, transferred);
    assert.equal(adopted.head.hash, expected.head.hash);
    assert.equal((await rpc(2, "eth_getBlockByNumber", ["0x" + commonHeight.toString(16), false])).hash, common.head.hash);
    assert.deepEqual(await rpc(2, "shell_getBlockSigners", [signerTag]), expectedSigners);
    assert.equal(await rpc(2, "eth_getTransactionCount", [miner.getAddress(), "latest"]), sameHeightForkScenario ? "0x4" : weightedForkScenario ? "0x6" : "0x3");
    const docs = await readFile(new URL("../../docs/JSON_RPC_API.md", import.meta.url), "utf8");
    const curl = docs.split("### shell_getBlockSigners")[1].split("### shell_verifyPqSignature")[0]
      .split("```bash\n").slice(1).map((block) => block.split("```")[0]).find((block) => block.includes("curl "));
    assert.ok(curl, "original one-block curl example");
    const originalRequest = spawnSync("sh", ["-c", curl.replace("http://localhost:8545", `http://127.0.0.1:${ports[2]}`)], {
      encoding: "utf8", timeout: 10000, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost" },
    });
    assert.equal(originalRequest.status, 0, originalRequest.stderr);
    result.forkOriginalCurl = JSON.parse(originalRequest.stdout);
    assert.deepEqual(result.forkOriginalCurl.result, await rpc(3, "shell_getBlockSigners", ["latest"]));
    assert.equal(await rpc(2, "eth_getTransactionReceipt", [orphanTx]), null);
    for (const hash of [...commonTransactions, branchTx, ...(tipTx ? [tipTx] : []), ...(heavyTx ? [heavyTx] : [])])
      assert.deepEqual(await rpc(2, "eth_getTransactionReceipt", [hash]), await rpc(3, "eth_getTransactionReceipt", [hash]));
    for (let index = nodes.length - 1; index >= 0; index--) await stop(index);
    await start(2, extraDirs[0], extraKeys[0], "fork-observer-reopen");
    const reopened = await observe(2, finalHeight, finalHeight, transferred);
    assert.equal(reopened.head.hash, expected.head.hash);
    assert.deepEqual(await rpc(2, "shell_getBlockSigners", [signerTag]), expectedSigners);
    assert.equal(await rpc(2, "eth_getTransactionReceipt", [orphanTx]), null);
    result.forkSync = { common, provisional, expected, adopted, reopened, expectedSigners };
    result.forkSyncVerified = true;
    result.finalHeight = finalHeight;
    result.passed = true;
    return;
  }
  if (quorumRecoveryScenario) {
    assert.equal(miner.signatureType, "SphincsSha2256f");
    assert.equal(miner.getPublicKey().length, 64);
    const expectedKeys = new Map(authorities.map((signer) => [
      signer.getAddress(), "0x" + Buffer.from(signer.getPublicKey()).toString("hex"),
    ]));
    result.adaptations.push("Two equal-weight SLH-DSA/ML-DSA authorities on full RocksDB; one temporarily goes offline. No quorum threshold or live-network change.");
    const members = await Promise.all([0, 1].map((i) => rpc(i, "shell_consensusInfo")));
    for (const view of members) {
      assert.deepEqual(view.validators.map((v) => v.address).sort(), [...expectedKeys.keys()].sort());
      assert.ok(view.validators.every((v) => v.weight === 1));
    }
    const finalized = async (i, entry) => {
      let block;
      for (let attempt = 0; attempt < 85; attempt++) {
        block = await rpc(i, "eth_getBlockByNumber", ["finalized", false]);
        if (block?.hash === entry.receipt.blockHash) break;
        await pause(250);
      }
      assert.equal(block?.hash, entry.receipt.blockHash, "both genuine authority votes finalize the block");
    };
    const recipientBefore = BigInt(await rpc(0, "eth_getBalance", [outsider.getAddress(), "latest"]));
    const transfer = (label) => confirmed(label, miner, [
      buildInnerCall(outsider.getAddress(), "0x", 100000, 1n),
    ], "0x1", false);
    const first = await transfer("two-authority finalized baseline");
    await finalized(0, first);
    await finalized(1, first);
    await stop(1);
    const second = await transfer("sealed block awaits missing authority vote");
    result.quorumRecovery = { offlineFinality: [], observations: [] };
    for (let attempt = 0; attempt < 12; attempt++) {
      const block = await rpc(0, "eth_getBlockByNumber", ["finalized", false]);
      result.quorumRecovery.offlineFinality.push(block.number);
      await save();
      assert.equal(block.hash, first.receipt.blockHash, "one of two validators cannot finalize a new block");
      await pause(500);
    }
    const lone = await rpc(0, "shell_getBlockSigners", ["0x2"]);
    assert.equal(lone.signers.length, 1);
    assert.equal(lone.signers[0].address, miner.getAddress());
    assert.equal(lone.signers[0].pqPubkey, expectedKeys.get(miner.getAddress()));
    assert.equal(lone.signers[0].signatureValid, true);
    result.quorumRecovery.beforeReturn = lone;
    await start(1, dirs[1], followerKey, "quorum-returned-authority", bootnode);
    await peerReady();
    let returned;
    for (let attempt = 0; attempt < 85; attempt++) {
      returned = await rpc(1, "eth_getBlockByNumber", ["latest", false]);
      result.quorumRecovery.returnedHead = { number: returned.number, hash: returned.hash };
      await save();
      if (returned.hash === second.receipt.blockHash) break;
      await pause(250);
    }
    assert.equal(returned.hash, second.receipt.blockHash, "returning validator recovers the missing sealed block without another transaction");
    await finalized(0, second);
    await finalized(1, second);
    const inspect = async (i, role) => {
      const snapshot = async () => ({
        head: await rpc(i, "eth_getBlockByNumber", ["latest", false]),
        nonce: await rpc(i, "eth_getTransactionCount", [miner.getAddress(), "latest"]),
        recipient: await rpc(i, "eth_getBalance", [outsider.getAddress(), "latest"]),
      });
      const before = await snapshot();
      assert.equal(before.head.hash, second.receipt.blockHash);
      assert.equal(BigInt(before.recipient), recipientBefore + 2n);
      const history = {};
      for (const tag of ["0x1", "0x2", "latest", "finalized"]) {
        const answer = await rpc(i, "shell_getBlockSigners", [tag]);
        assert.deepEqual(answer.signers.map((v) => v.address).sort(), [...expectedKeys.keys()].sort());
        for (const signer of answer.signers) {
          assert.equal(signer.pqPubkey, expectedKeys.get(signer.address));
          assert.equal(signer.signatureValid, true);
        }
        history[tag] = answer;
      }
      assert.deepEqual(await snapshot(), before, "quorum history queries preserve head and accounts");
      if (result.quorumRecovery.observations.length)
        assert.deepEqual(history, result.quorumRecovery.observations[0].history);
      result.quorumRecovery.observations.push({ role, history, readOnly: true });
      await save();
    };
    await inspect(0, "authority-0");
    await inspect(1, "returned-authority-1");
    await stop(1);
    await start(1, dirs[1], followerKey, "quorum-reopened-authority", bootnode);
    await peerReady();
    await finalized(1, second);
    await inspect(1, "reopened-authority-1");
    result.quorumRecoveryVerified = true;
    result.finalHeight = height;
    result.passed = true;
    return;
  }
  if (blockSignersScenario) {
    if (sphincsSignersScenario) {
      assert.equal(miner.signatureType, "SphincsSha2256f");
      assert.equal(miner.getPublicKey().length, 64, "SLH-DSA-SHA2-256f public-key width");
    }
    result.signerAlgorithm = miner.signatureType;
    const recipientBefore = BigInt(await rpc(0, "eth_getBalance", [outsider.getAddress(), "latest"]));
    // Use signed transfers and normal import/finality, with independently known keys.
    for (let block = 1; block <= 21; block++)
      await confirmed(`signer history ${block}`, miner, [
        buildInnerCall(outsider.getAddress(), "0x", 100000, 1n),
      ], "0x1", false);
    assert.equal(
      BigInt(await rpc(0, "eth_getBalance", [outsider.getAddress(), "latest"])),
      recipientBefore + 21n, "all signed transfers credit their recipient",
    );
    const last = result.transactions.at(-1);
    await compare(last.hash);
    const first = result.transactions[0];
    for (let attempt = 0; attempt < 100; attempt++) {
      if (await rpc(1, "eth_getTransactionByHash", [first.hash]) === null) break;
      await pause(250);
    }
    assert.ok(await rpc(0, "eth_getTransactionByHash", [first.hash]),
      "full producer retains the signed transaction body");
    assert.equal(await rpc(1, "eth_getTransactionByHash", [first.hash]), null,
      "light follower actually pruned the signed transaction body");
    const expectedKey = "0x" + Buffer.from(miner.getPublicKey()).toString("hex");
    const violations = [];
    const observations = [];
    const invalidParams = [[], [1], [null], ["latest", "0x1"], {},
      { block: 1 }, { block: "latest", unexpected: 1 }];
    const inspect = async (i, label) => {
      const snapshot = async () => ({
        head: await rpc(i, "eth_getBlockByNumber", ["latest", false]),
        nonce: await rpc(i, "eth_getTransactionCount", [miner.getAddress(), "latest"]),
        balance: await rpc(i, "eth_getBalance", [miner.getAddress(), "latest"]),
      });
      const before = await snapshot();
      const finalized = await rpc(i, "eth_getBlockByNumber", ["finalized", false]);
      const history = {};
      for (const tag of ["latest", "pending", "safe", "finalized", "0x1", "0x2", "0x15", "earliest"]) {
        const answer = await rpc(i, "shell_getBlockSigners", [tag]);
        if (tag === "earliest") {
          assert.deepEqual(answer, { blockNumber: "0x0", signers: [] });
        } else {
          const number = ["latest", "pending"].includes(tag) ? before.head.number
            : ["safe", "finalized"].includes(tag) ? finalized.number : tag;
          assert.equal(answer.blockNumber, number);
          assert.equal(answer.signers.length, 1, "one configured authority signs each block");
          assert.equal(answer.signers[0].address, miner.getAddress());
          assert.equal(answer.signers[0].pqPubkey, expectedKey,
            "historical signer key matches the generated authority, not the follower key");
          assert.equal(answer.signers[0].signatureValid, true);
        }
        history[tag] = answer;
      }
      for (const tag of ["nonsense", "0xzz", "0xffffffffffffffff"])
        await assert.rejects(() => rpc(i, "shell_getBlockSigners", [tag]));
      const request = async (params) => paced(async () => {
        const response = await fetch(`http://127.0.0.1:${ports[i]}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", method: "shell_getBlockSigners", params, id: 1 }),
          signal: AbortSignal.timeout(5000),
        });
        assert.equal(response.status, 200);
        return response.json();
      });
      assert.deepEqual((await request({ block: "latest" })).result, history.latest);
      for (const params of invalidParams) {
        const answer = await request(params);
        if (answer.error?.code !== -32602)
          violations.push({ label, transport: "http", params, answer });
      }
      const socket = new WebSocket(`ws://127.0.0.1:${ports[i]}`);
      try {
        await new Promise((done, fail) => {
          socket.addEventListener("open", done, { once: true });
          socket.addEventListener("error", fail, { once: true });
        });
        let id = 0;
        const wsRequest = (params) => paced(() => new Promise((done, fail) => {
          const requestId = ++id;
          const timeout = setTimeout(() => {
            socket.removeEventListener("message", receive);
            fail(Error("block signers WebSocket request timed out"));
          }, 5000);
          const receive = ({ data }) => {
            const answer = JSON.parse(data);
            if (answer.id !== requestId) return;
            clearTimeout(timeout);
            socket.removeEventListener("message", receive);
            done(answer);
          };
          socket.addEventListener("message", receive);
          socket.send(JSON.stringify({ jsonrpc: "2.0", method: "shell_getBlockSigners", params, id: requestId }));
        }));
        assert.deepEqual((await wsRequest(["latest"])).result, history.latest);
        assert.deepEqual((await wsRequest({ block: "latest" })).result, history.latest);
        for (const params of invalidParams) {
          const answer = await wsRequest(params);
          if (answer.error?.code !== -32602)
            violations.push({ label, transport: "websocket", params, answer });
        }
      } finally { socket.close(); }
      assert.deepEqual(await snapshot(), before, "signer queries and rejections preserve head and account state");
      if (observations.length) assert.deepEqual(history, observations[0].history);
      observations.push({ label, history, readOnly: true });
      result.blockSigners = { observations, violations };
      await save();
    };
    await inspect(0, "full-producer");
    await inspect(1, "pruned-follower");
    await stop(1);
    await start(1, dirs[1], followerKey, "signers-restarted-follower", bootnode);
    await peerReady();
    // Backfill may briefly restore an old body; observe the final retained window.
    for (let attempt = 0; attempt < 100; attempt++) {
      const log = await readFile(join(out, "signers-restarted-follower-node.log"), "utf8");
      if (log.includes("L4: historical body back-fill complete") &&
          await rpc(1, "eth_getTransactionByHash", [first.hash]) === null) break;
      await pause(250);
    }
    assert.equal(await rpc(1, "eth_getTransactionByHash", [first.hash]), null,
      "reopened light follower retains the pruned window");
    await inspect(1, "pruned-follower-reopened");
    result.finalHeight = height;
    result.blockSigners.positiveHistoryVerified = true;
    result.blockSigners.reopenVerified = true;
    await save();
    assert.deepEqual(violations, [], "missing, wrong-type and extra parameters must return -32602");
    result.blockSignersVerified = true;
    result.passed = true;
    return;
  }
  if (epochScenario) {
    const read = (label, signer = miner) =>
      confirmed(label, signer, [], "0x1", true, true);
    const write = (label, data) =>
      confirmed(label, miner, [native(data)], "0x1", true, true);
    const restart = async (entry) => {
      if (prunedEpochScenario) {
        const boundary = Math.floor(height / 5) * 5;
        // The current finalized boundary body may still be inside retention at height 21.
        const bodyHeight = height === 21 ? boundary - 5 : boundary;
        const tag = "0x" + boundary.toString(16);
        const bodyTag = "0x" + bodyHeight.toString(16);
        const retained = await rpc(0, "eth_getBlockByNumber", [bodyTag, false]);
        assert.ok(retained?.transactions.length > 0, "producer retains the boundary body");
        assert.equal(await rpc(1, "eth_getBlockByNumber", [bodyTag, false]), null,
          "follower actually pruned an old boundary body");
        const boundaryNonces = await Promise.all([0, 1].map((i) =>
          rpc(i, "eth_getTransactionCount", [miner.getAddress(), tag])));
        assert.equal(boundaryNonces[1], boundaryNonces[0],
          "follower retains the current epoch boundary state");
        assert.notEqual(boundaryNonces[1], await rpc(1, "eth_getTransactionCount", [
          miner.getAddress(), "latest"]), "boundary reads do not substitute the head");
        let expiredBoundaryState;
        if (boundary >= 10) {
          const expiredTag = "0x" + (boundary - 5).toString(16);
          await assert.rejects(() => rpc(1, "eth_getTransactionCount", [
            miner.getAddress(), expiredTag]), (error) => {
              expiredBoundaryState = { block: expiredTag, code: error.code, message: error.message };
              return Number.isInteger(error.code) && ![-32601, -32602].includes(error.code);
            }, "the preceding epoch state has expired while the current boundary remains readable");
        }
        const log = await readFile(join(out, nodeLogLabels[1] + "-node.log"), "utf8");
        assert.ok(log.includes("body pruner: expired old block bodies"));
        assert.ok(log.includes("state trie pruning deleted old snapshots"));
        entry.epochPruning = { boundary, bodyHeight, boundaryNonces, bodyPruned: true, statePruned: true, expiredBoundaryState };
      }
      await stop(1);
      await start(1, dirs[1], followerKey, `epoch-restart-${height}`, bootnode);
      await peerReady();
      if (prunedEpochScenario) {
        // Observe retention after the historical response, not before it arrives.
        let complete = false;
        for (let attempt = 0; attempt < 80; attempt++) {
          const log = await readFile(join(out, nodeLogLabels[1] + "-node.log"), "utf8");
          if (log.includes("L4: historical body back-fill complete")) {
            complete = true;
            break;
          }
          await pause(250);
        }
        assert.ok(complete, "restarted follower completed historical backfill");
      }
      entry.epochRestart = await compare(entry.hash);
    };
    await write("weight 3 pending", weight(3));
    await read("register candidate identity", outsider);
    await read("pre-boundary read 3");
    await read("pre-boundary read 4");
    expectedConsensusWeight = 3;
    await read("weight 3 activates at boundary 5");
    const pendingWeight = await write("weight 5 pending", weight(5));
    const at7 = await read("mid-epoch read 7");
    assert.equal((await state(0)).validator.weight, 5);
    await restart(at7);
    await read("pre-boundary read 8");
    await read("pre-boundary read 9");
    expectedConsensusWeight = 5;
    await read("weight 5 activates at boundary 10");
    const member = outsider.getAddress();
    const pendingAdd = await write(
      "member addition pending",
      "0x4d238c8e" + member.slice(2),
    );
    const at12 = await read("mid-epoch read 12");
    await restart(at12);
    await read("pre-boundary read 13");
    await read("pre-boundary read 14");
    expectedMembers = [miner.getAddress(), member];
    await read("member addition activates at boundary 15");
    const pendingRemove = await write(
      "member removal pending",
      "0x40a141ff" + member.slice(2),
    );
    const at17 = await read("mid-epoch read 17");
    await restart(at17);
    await read("pre-boundary read 18");
    await read("pre-boundary read 19");
    expectedMembers = [miner.getAddress()];
    await read("member removal activates at boundary 20");
    const at21 = await read("mid-epoch read 21");
    await restart(at21);
    for (const entry of [pendingWeight, pendingAdd, pendingRemove]) {
      for (let i = 0; i < 2; i++) {
        const before = await state(i);
        if (pruneFollower && i === 1) {
          assert.equal(await rpc(i, "eth_getBlockByNumber", [entry.receipt.blockNumber, false]), null,
            "old replay bodies lie outside the rolling window");
          await assert.rejects(() => rpc(i, "eth_getTransactionCount", [
            miner.getAddress(), entry.receipt.blockNumber]),
            (error) => {
              entry.prunedStateRejection = { code: error.code, message: error.message };
              return Number.isInteger(error.code) &&
                ![-32601, -32602].includes(error.code);
            }, "old state is unavailable rather than substituted with the head");
          assert.deepEqual(await state(i), before);
          continue;
        }
        assert.deepEqual(
          await rpc(i, "debug_traceTransaction", [
            entry.hash,
            { tracer: "callTracer" },
          ]),
          entry.trace,
        );
        assert.deepEqual(await state(i), before);
      }
    }
    result.epochRestarts = [7, 12, 17, 21];
    result.pendingGovernanceHistoryVerified = !prunedEpochScenario;
    result.prunedEpochRecoveryVerified = prunedEpochScenario;
    const rpcDocs = await readFile(
      new URL("../../docs/JSON_RPC_API.md", import.meta.url),
      "utf8",
    );
    const epochExample = rpcDocs
      .split("### shell_getEpochInfo")[1]
      .split("### shell_getValidatorVotes")[0]
      .split("```bash\n")
      .slice(1)
      .map((block) => block.split("```")[0])
      .find((block) => block.includes("curl "));
    assert.ok(epochExample, "canonical epoch curl example exists");
    if (process.platform !== "win32") {
      const example = spawnSync(
        "sh",
        ["-c", epochExample.replace("http://localhost:8545", `http://127.0.0.1:${ports[1]}`)],
        {
          encoding: "utf8",
          timeout: 10000,
          env: { ...process.env, NO_PROXY: "127.0.0.1,localhost" },
        },
      );
      assert.equal(example.status, 0, example.stderr);
      result.epochExample = JSON.parse(example.stdout);
      assert.deepEqual(result.epochExample.result, at21.epochRestart.epochInfo[1]);
    }
    result.epochRpcVerified = true;
    result.finalHeight = height;
    result.passed = true;
    return;
  }
  const expected = "0x" + word(32) + word(1) + miner.getAddress().slice(2);
  const before = await confirmed(
    "AA read before activation retains legacy output",
    outsider,
    [native(getValidators)],
  );
  assert.equal(before.trace.calls[0].output, "0x" + word(0));
  const direct = await confirmed(
    "direct read control",
    outsider,
    [],
    "0x1",
    true,
    true,
  );
  assert.equal(direct.trace.output, expected);
  const active = await confirmed("native AA read at activation", outsider, [
    native(getValidators),
  ]);
  assert.equal(active.trace.calls[0].output, expected);
  await confirmed(
    "non-validator cannot change weight",
    outsider,
    [native(weight(2))],
    "0x0",
  );
  assert.equal((await state(0)).validator.weight, 1);
  await confirmed(
    "weight change rolls back after later failure",
    miner,
    [native(weight(2)), bad],
    "0x0",
  );
  assert.equal((await state(0)).validator.weight, 1);
  await confirmed("weight change commits", miner, [native(weight(2))]);
  assert.equal((await state(0)).validator.weight, 2);
  await confirmed(
    "out-of-gas native mutation rolls back",
    miner,
    [native(weight(3), 22000)],
    "0x0",
  );
  assert.equal((await state(0)).validator.weight, 2);
  await confirmed(
    "native value rejected",
    miner,
    [native(weight(3), 200000, 1n)],
    "0x0",
  );
  assert.equal((await state(0)).validator.weight, 2);
  // Cross-native rollback: successful guardian setup must not escape a failed batch.
  const guardians = encodeSetGuardiansCalldata([miner.getAddress()], 1, 100);
  const manager = (data) => buildInnerCall(accountManagerAddress, data, 200000);
  await confirmed(
    "AccountManager metadata rolls back with Registry failure",
    outsider,
    [manager(guardians), bad],
    "0x0",
  );
  await confirmed(
    "rolled-back guardians cannot submit recovery",
    miner,
    [
      manager(
        encodeSubmitRecoveryCalldata(
          outsider.getAddress(),
          miner.getPublicKey(),
          miner.algorithmId,
        ),
      ),
    ],
    "0x0",
  );
  const policyBefore = (await state(0)).algorithms;
  await confirmed(
    "algorithm policy rolls back with metadata",
    miner,
    [native(deprecate), bad],
    "0x0",
  );
  assert.deepEqual((await state(0)).algorithms, policyBefore);
  const deprecated = await confirmed("algorithm policy commits", miner, [
    native(deprecate),
  ]);
  assert.equal(
    (await state(0)).algorithms.find((x) => x.algo === "SphincsSha2256f")
      .status,
    "deprecated",
  );
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
        "history must not mutate live state",
      );
    }
  }
  result.historicalReplayVerified = true;
  await stop(1);
  const offline = await confirmed(
    "weight changes while follower offline",
    miner,
    [native(weight(3))],
    "0x1",
    false,
  );
  await start(1, dirs[1], followerKey, "follower-restart", bootnode);
  await peerReady();
  result.catchupAfterRestart = await compare(offline.hash);
  assert.equal((await state(1)).validator.weight, 3);
  assert.equal(
    (await state(1)).algorithms.find((x) => x.algo === "SphincsSha2256f")
      .status,
    "deprecated",
  );
  assert.deepEqual(
    await rpc(1, "debug_traceTransaction", [
      deprecated.hash,
      { tracer: "callTracer" },
    ]),
    deprecated.trace,
  );
  // Native membership events preserve legacy receipts before block 16, then
  // expose the complete indexed identifier on direct and AA execution paths.
  const { keccak256, toHex } = createRequire(
    resolve(process.env.SHELL_SDK_ENTRY),
  )("viem");
  const member = outsider.getAddress();
  const add = "0x4d238c8e" + member.slice(2);
  const remove = "0x40a141ff" + member.slice(2);
  const addTopic = keccak256(toHex("ValidatorAdded(address)"));
  const removeTopic = keccak256(toHex("ValidatorRemoved(address)"));
  const eventStart = result.transactions.length;
  expectedMembers = [miner.getAddress(), member];
  const legacyAdd = await confirmed(
    "legacy direct add event",
    miner,
    [native(add)],
    "0x1",
    true,
    true,
  );
  expectedMembers = [miner.getAddress()];
  const legacyRemove = await confirmed(
    "legacy direct remove event",
    miner,
    [native(remove)],
    "0x1",
    true,
    true,
  );
  for (const entry of [legacyAdd, legacyRemove]) {
    assert.equal(entry.receipt.logs.length, 1);
    assert.equal(entry.receipt.logs[0].topics.length, 1);
    assert.equal(
      entry.receipt.logs[0].data.toLowerCase(),
      "0x" + "0".repeat(24) + member.slice(-40).toLowerCase(),
    );
  }
  expectedMembers = [miner.getAddress(), member];
  const indexedAdd = await confirmed("indexed AA add at activation", miner, [
    native(add),
  ]);
  assert.equal(Number(BigInt(indexedAdd.receipt.blockNumber)), 16);
  const failed = await confirmed(
    "AA remove event rolls back with later failure",
    miner,
    [native(remove), bad],
    "0x0",
  );
  assert.deepEqual(failed.receipt.logs, []);
  assert.ok(
    (await state(0)).consensusValidators.some(
      (v) =>
        (typeof v === "string" ? v : v.address)?.toLowerCase() ===
        member.toLowerCase(),
    ),
  );
  expectedMembers = [miner.getAddress()];
  const indexedRemove = await confirmed("indexed AA remove", miner, [
    native(remove),
  ]);
  expectedMembers = [miner.getAddress(), member];
  const directAdd = await confirmed(
    "indexed direct add",
    miner,
    [native(add)],
    "0x1",
    true,
    true,
  );
  expectedMembers = [miner.getAddress()];
  const directRemove = await confirmed(
    "indexed direct remove",
    miner,
    [native(remove)],
    "0x1",
    true,
    true,
  );
  const expectedEvents = [
    [indexedAdd, addTopic],
    [indexedRemove, removeTopic],
    [directAdd, addTopic],
    [directRemove, removeTopic],
  ];
  for (const [entry, topic] of expectedEvents) {
    assert.equal(entry.receipt.logs.length, 1);
    assert.equal(
      entry.receipt.logs[0].address.toLowerCase(),
      validatorRegistryAddress.toLowerCase(),
    );
    assert.deepEqual(
      entry.receipt.logs[0].topics.map((v) => v.toLowerCase()),
      [topic, member.toLowerCase()],
    );
    assert.equal(entry.receipt.logs[0].data, "0x");
  }
  const filter = {
    fromBlock: "0x0",
    toBlock: "latest",
    address: validatorRegistryAddress,
    topics: [null, member],
  };
  const logs = await rpc(0, "eth_getLogs", [filter]);
  assert.deepEqual(
    logs.map((l) => l.transactionHash),
    expectedEvents.map(([e]) => e.hash),
  );
  assert.deepEqual(await rpc(1, "eth_getLogs", [filter]), logs);
  for (const entry of result.transactions.slice(eventStart)) {
    for (let i = 0; i < 2; i++) {
      const before = await state(i);
      assert.deepEqual(
        await rpc(i, "debug_traceTransaction", [
          entry.hash,
          { tracer: "callTracer" },
        ]),
        entry.trace,
      );
      assert.deepEqual(await state(i), before);
    }
  }
  await stop(1);
  await start(1, dirs[1], followerKey, "event-follower-restart", bootnode);
  await peerReady();
  await compare(directRemove.hash);
  assert.deepEqual(await rpc(1, "eth_getLogs", [filter]), logs);
  result.indexedNativeEventsVerified = true;
  result.finalHeight = height;
  result.passed = true;
}
try {
  await runScenario();
} catch (error) {
  result.error = String(error);
  throw error;
} finally {
  for (let index = nodes.length - 1; index >= 0; index--) await stop(index);
  result.nodesStopped = nodes.every((x) => !x);
  result.endedAt = new Date().toISOString();
  await save();
  for (const signer of signers) signer.dispose();
  console.log(`Acceptance report: ${join(out, "runtime.json")}`);
}
