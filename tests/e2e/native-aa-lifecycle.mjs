#!/usr/bin/env node
// Real signed native-AA lifecycle acceptance against an isolated CLI/RocksDB node.
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
  accountManagerAddress,
  encodeSetGuardiansCalldata,
  encodeSubmitRecoveryCalldata,
  encodeExecuteRecoveryCalldata,
  encodeCancelRecoveryCalldata,
  encodeSetValidationCodeCalldata,
  encodeClearValidationCodeCalldata,
} = await import(pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY)).href);
const binary = resolve(
  process.env.NODE_BIN ??
    fileURLToPath(new URL("../../target/debug/shell-node", import.meta.url)),
);
const out = await mkdtemp(join(tmpdir(), "shell-native-aa-"));
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
const listener = createServer();
await new Promise((done, fail) => {
  listener.once("error", fail);
  listener.listen(0, "127.0.0.1", done);
});
const port = listener.address().port;
await new Promise((done) => listener.close(done));
const fresh = () => new ShellSigner("MlDsa65", MlDsa65Adapter.generate());
const old = fresh(),
  replacement = new ShellSigner(
    "MlDsa65",
    MlDsa65Adapter.generate(),
    old.getAddress(),
  );
const [g1, g2, g3, outsider] = [fresh(), fresh(), fresh(), fresh()];
const signers = [miner, old, replacement, g1, g2, g3, outsider];
const provider = createShellProvider({
    rpcHttpUrl: `http://127.0.0.1:${port}`,
  }),
  pause = (ms) => new Promise((r) => setTimeout(r, ms));
// Serialize reads and submissions below the default RPC rate limit, including
// snapshot reads requested concurrently. Propagate each failure to its caller.
let requestQueue = Promise.resolve();
function paced(request) {
  const task = requestQueue.then(() => pause(100)).then(request);
  requestQueue = task.catch(() => {});
  return task;
}
const rpc = (method, params = []) =>
  paced(() => provider.client.request({ method, params }));
const send = (signed) => paced(() => provider.sendTransaction(signed));
let node,
  height = 0;
const nonces = new Map();
const result = {
  startedAt: new Date().toISOString(),
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
  transactions: [],
  rejections: [],
  adaptations: [
    "Requires a compatible built SDK with transaction wire format v2 (0.14.0-rc.1 tested); this is source acceptance, not public npm availability.",
    "Actual signed transactions through CLI/RPC/RocksDB; explicit dev mining and synthetic timestamps; no wall-clock or production-scale claim.",
    "Native AccountManager AA activated at genesis only in this isolated fixture. This extends existing native-AA acceptance to mature guardian recovery, failed later inner-call rollback, restart and historical replay. Custom validation policies below are test-only value filters, not authentication examples.",
  ],
};
async function stop() {
  if (!node) return;
  const child = node;
  if (!child.pid) {
    node = undefined;
    return;
  }
  const running = () => child.exitCode === null && child.signalCode === null;
  if (running()) child.kill("SIGTERM");
  for (let i = 0; i < 80 && running(); i++) await pause(250);
  if (running()) {
    child.kill("SIGKILL");
    await new Promise((done) => child.once("exit", done));
  }
  assert.ok(!running());
  node = undefined;
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    stop().finally(() => process.exit(signal === "SIGINT" ? 130 : 143));
  });
async function start(data, label) {
  const command = [
    "run",
    "--datadir",
    data,
    "--keystore",
    keyPath,
    "--password-file",
    passwordPath,
    "--rpc-addr",
    `127.0.0.1:${port}`,
    "--metrics-addr",
    "127.0.0.1:0",
    "--block-time",
    "600000",
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
    "eth,net,web3,shell,debug,trace,evm",
    "--storage-profile",
    "full",
  ];
  const fd = openSync(join(out, label + "-node.log"), "w");
  node = spawn(binary, command, { stdio: ["ignore", fd, fd] });
  closeSync(fd);
  let spawnError;
  node.once("error", (error) => {
    spawnError = error;
  });
  for (let i = 0; i < 160; i++) {
    if (spawnError) throw spawnError;
    assert.equal(node.exitCode, null, "node exited");
    assert.equal(node.signalCode, null, "node signaled");
    try {
      await rpc("eth_blockNumber");
      return;
    } catch {
      await pause(250);
    }
  }
  throw Error("startup timeout");
}
try {
  const data = join(out, "data");
  await mkdir(data);
  const genesis = {
    chain_id: 1337,
    chain_name: "native-aa-acceptance",
    network_type: "Dev",
    timestamp: 0,
    gas_limit: 30000000,
    extra_data: "native-aa-acceptance",
    alloc: {},
    boot_nodes: [],
  };
  genesis.timestamp = Math.floor(Date.now() / 1000) - 600;
  genesis.consensus = {
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
  };
  genesis.registered_key_algorithm_height = 0;
  genesis.aa_account_manager_height = 0;
  genesis.fee_accounting_activation_height = 0;
  for (const x of signers)
    genesis.alloc[x.getAddress()] = {
      balance: "0x3635c9adc5dea00000",
      nonce: 0,
      code: null,
      storage: null,
    };
  await writeFile(join(data, "genesis.json"), JSON.stringify(genesis, null, 2));
  await start(data, "initial");
  const mine = async () => {
    height++;
    await rpc("evm_setNextBlockTimestamp", [genesis.timestamp + height * 2]);
    await rpc("evm_mine", [1]);
    assert.equal(Number(BigInt(await rpc("eth_blockNumber"))), height);
  };
  const build = async (
    signer,
    calldata,
    to = accountManagerAddress,
    lateFailure = false,
  ) => {
    const innerCalls = [buildInnerCall(to, calldata, 500000)];
    if (lateFailure)
      innerCalls.push(
        buildInnerCall(accountManagerAddress, "0xffffffff", 100000),
      );
    const batch = buildBatchTransaction({
      chainId: 1337,
      nonce: nonces.get(signer.getAddress()) ?? 0,
      innerCalls,
      gasLimit: 3000000,
    });
    return signer.buildSignedTransaction({
      tx: batch.tx,
      aaBundle: batch.aa_bundle,
      includePublicKey: true,
    });
  };
  async function confirmed(
    label,
    signer,
    calldata,
    status = "0x1",
    error = undefined,
    to = accountManagerAddress,
    lateFailure = false,
  ) {
    const hash = await send(await build(signer, calldata, to, lateFailure));
    await mine();
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    assert.equal(receipt?.status, status, label);
    assert.equal(Number(BigInt(receipt.blockNumber)), height);
    nonces.set(signer.getAddress(), (nonces.get(signer.getAddress()) ?? 0) + 1);
    const trace = await rpc("debug_traceTransaction", [hash]);
    assert.equal(trace.failed, status === "0x0", label);
    const output = Buffer.from(
      String(trace.output).replace(/^0x/, ""),
      "hex",
    ).toString();
    if (error) assert.match(output, error, label);
    result.transactions.push({ label, hash, receipt, trace });
    await writeFile(
      join(out, "runtime-progress.json"),
      JSON.stringify(result, null, 2),
    );
    return height;
  }
  const account = old.getAddress(),
    vote = encodeSubmitRecoveryCalldata(
      account,
      replacement.getPublicKey(),
      replacement.algorithmId,
    ),
    execute = encodeExecuteRecoveryCalldata(account),
    cancel = encodeCancelRecoveryCalldata(account),
    settings = encodeSetGuardiansCalldata(
      [g1.getAddress(), g2.getAddress(), g3.getAddress()],
      2,
      100,
    );
  await confirmed("set-2-of-3", old, settings);
  await confirmed("outsider-cannot-vote", outsider, vote, "0x0", /guardian/i);
  await confirmed("first-vote", g1, vote);
  await confirmed("repeated-vote-is-idempotent", g1, vote);
  await confirmed(
    "repeated-vote-does-not-reach-threshold",
    outsider,
    execute,
    "0x0",
    /not.*matur|matur/i,
  );
  const threshold = await confirmed(
    "second-distinct-vote-reaches-threshold",
    g2,
    vote,
  );
  result.thresholdBlock = threshold;
  result.expectedExecutableBlock = threshold + 100;
  await confirmed(
    "non-owner-cannot-cancel",
    g1,
    cancel,
    "0x0",
    /unauthorized/i,
  );
  await confirmed(
    "owner-cannot-replace-active-guardians",
    old,
    settings,
    "0x0",
    /recovery.*active/i,
  );
  await confirmed(
    "conflicting-key-vote-rejected",
    g3,
    encodeSubmitRecoveryCalldata(account, g3.getPublicKey(), g3.algorithmId),
    "0x0",
    /recovery.*active/i,
  );
  while (height < threshold + 98) await mine();
  await confirmed(
    "99-block-delay-rejected",
    outsider,
    execute,
    "0x0",
    /matur/i,
  );
  await stop();
  await start(data, "pending-restart");
  const beforeRecoveryKey = await rpc("shell_getPqPubkey", [account]);
  await confirmed(
    "mature-recovery-later-call-failure-rolls-back",
    outsider,
    execute,
    "0x0",
    /unknown function selector/i,
    accountManagerAddress,
    true,
  );
  assert.equal(
    await rpc("shell_getPqPubkey", [account]),
    beforeRecoveryKey,
    "failed bundle must preserve old root",
  );
  await confirmed(
    "old-root-still-usable-after-failed-recovery",
    old,
    "0x",
    "0x1",
    undefined,
    outsider.getAddress(),
  );
  await confirmed(
    "mature-recovery-retry-uses-preserved-proposal",
    outsider,
    execute,
  );
  assert.equal(
    await rpc("shell_getPqPubkey", [account]),
    "0x" + Buffer.from(replacement.getPublicKey()).toString("hex"),
  );
  result.matureRecoveryRollbackVerified = true;
  await confirmed(
    "replacement-key-usable",
    replacement,
    "0x",
    "0x1",
    undefined,
    outsider.getAddress(),
  );
  const before = await rpc("eth_getTransactionCount", [account, "latest"]);
  let staleError;
  try {
    await send(await build(old, "0x", outsider.getAddress()));
  } catch (e) {
    staleError = String(e);
  }
  assert.match(staleError ?? "", /pubkey|signature|key/i);
  assert.equal(
    await rpc("eth_getTransactionCount", [account, "latest"]),
    before,
  );
  result.rejections.push({
    label: "old-key-rejected-without-nonce-change",
    error: staleError,
  });
  await confirmed(
    "executed-proposal-cleared",
    outsider,
    execute,
    "0x0",
    /no.*recovery|proposal.*not/i,
  );
  await confirmed("new-guardian-config", replacement, settings);
  await confirmed("new-subthreshold-proposal", g1, vote);
  await confirmed("owner-cancels-subthreshold", replacement, cancel);
  await confirmed(
    "cancelled-proposal-not-executable",
    outsider,
    execute,
    "0x0",
    /no.*recovery|proposal.*not/i,
  );
  await confirmed("new-vote-does-not-inherit-cancelled-votes", g2, vote);
  await confirmed(
    "old-vote-did-not-survive",
    outsider,
    execute,
    "0x0",
    /matur/i,
  );
  await confirmed("fresh-second-vote", g1, vote);
  await confirmed("owner-cancels-threshold-proposal", replacement, cancel);
  await confirmed(
    "threshold-cancelled-proposal-not-executable",
    outsider,
    execute,
    "0x0",
    /no.*recovery|proposal.*not/i,
  );
  await confirmed(
    "owner-reconfigures-after-cancellation",
    replacement,
    encodeSetGuardiansCalldata([g3.getAddress()], 1, 100),
  );
  const snapshot = async () =>
    Promise.all(
      signers.flatMap((s) => [
        rpc("eth_getTransactionCount", [s.getAddress(), "latest"]),
        rpc("eth_getBalance", [s.getAddress(), "latest"]),
        rpc("shell_getPqPubkey", [s.getAddress()]),
      ]),
    );
  const state = await snapshot();
  for (const t of result.transactions)
    assert.deepEqual(
      await rpc("debug_traceTransaction", [t.hash]),
      t.trace,
      t.label + " history",
    );
  assert.deepEqual(await snapshot(), state);
  result.historicalReplayNoAccountMutation = true;
  await stop();
  await start(data, "final-restart");
  assert.deepEqual(await snapshot(), state);
  await confirmed(
    "recovered-key-after-restart",
    replacement,
    "0x",
    "0x1",
    undefined,
    outsider.getAddress(),
  );
  result.pendingAndCompletedRestartVerified = true; // Both policies read the V2 ABI value word (byte offset 4 + 4 * 32).
  // Rejecting different transfer values distinguishes actual policy execution.
  // They intentionally do not authenticate: use only these isolated test accounts.
  const policies = [
    {
      code: "6084356007141560005260206000f3",
      hash: "0x64f5cc5d1ab8a616e8f8bd98cbfdd62fc8e6231d197e48251d50e5a27d1b39a2",
    },
    {
      code: "6084356009141560005260206000f3",
      hash: "0x04aa9f05656d6e42ba0583d91f5e83970684b95225c1e5f6baf7adae1644fc39",
    },
  ];
  const customStart = result.transactions.length;
  for (const [i, policy] of policies.entries()) {
    const size = (policy.code.length / 2).toString(16).padStart(4, "0");
    const tx = buildTransaction({
      chainId: 1337,
      nonce: nonces.get(miner.getAddress()) ?? 0,
      to: null,
      value: 0n,
      data: "0x61" + size + "61000f60003961" + size + "6000f3" + policy.code,
      gasLimit: 3000000,
    });
    const hash = await send(
      await miner.buildSignedTransaction({ tx, includePublicKey: true }),
    );
    await mine();
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    assert.equal(receipt.status, "0x1");
    nonces.set(miner.getAddress(), (nonces.get(miner.getAddress()) ?? 0) + 1);
    assert.equal(
      await rpc("eth_getCode", [receipt.contractAddress, "latest"]),
      "0x" + policy.code,
    );
    result.transactions.push({
      label: "deploy-value-filter-" + i,
      hash,
      receipt,
      trace: await rpc("debug_traceTransaction", [hash]),
    });
  }
  const probe = async (value) => {
    const batch = buildBatchTransaction({
      chainId: 1337,
      nonce: nonces.get(account) ?? 0,
      innerCalls: [buildInnerCall(outsider.getAddress(), "0x", 500000, value)],
      gasLimit: 3000000,
    });
    return replacement.buildSignedTransaction({
      tx: batch.tx,
      aaBundle: batch.aa_bundle,
      includePublicKey: true,
    });
  };
  async function valueAllowed(label, value) {
    const before = BigInt(
      await rpc("eth_getBalance", [outsider.getAddress(), "latest"]),
    );
    const hash = await send(await probe(value));
    await mine();
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    assert.equal(receipt.status, "0x1", label);
    nonces.set(account, (nonces.get(account) ?? 0) + 1);
    assert.equal(
      BigInt(await rpc("eth_getBalance", [outsider.getAddress(), "latest"])) -
        before,
      value,
      label,
    );
    result.transactions.push({
      label,
      hash,
      receipt,
      trace: await rpc("debug_traceTransaction", [hash]),
    });
  }
  async function valueRejected(label, value) {
    const before = await snapshot();
    let error;
    try {
      await send(await probe(value));
    } catch (e) {
      error = String(e);
    }
    assert.match(error ?? "", /validation contract rejected/i, label);
    assert.deepEqual(await snapshot(), before, label);
    result.rejections.push({ label, error, stateUnchanged: true });
  }
  const setA = encodeSetValidationCodeCalldata(policies[0].hash),
    setB = encodeSetValidationCodeCalldata(policies[1].hash),
    clear = encodeClearValidationCodeCalldata();
  await confirmed(
    "failed-set-policy-rolls-back",
    replacement,
    setA,
    "0x0",
    /unknown function selector/i,
    accountManagerAddress,
    true,
  );
  await valueAllowed("builtin-after-failed-set", 7n);
  await confirmed("set-policy-A", replacement, setA);
  await valueRejected("policy-A-rejects-seven", 7n);
  await valueAllowed("policy-A-allows-nine", 9n);
  await confirmed(
    "failed-policy-replacement-rolls-back",
    replacement,
    setB,
    "0x0",
    /unknown function selector/i,
    accountManagerAddress,
    true,
  );
  await valueRejected("policy-A-retained-after-failed-replacement", 7n);
  await confirmed("replace-with-policy-B", replacement, setB);
  await valueAllowed("policy-B-allows-seven", 7n);
  await valueRejected("policy-B-rejects-nine", 9n);
  const installedState = await snapshot();
  await stop();
  await start(data, "policy-restart");
  assert.deepEqual(await snapshot(), installedState);
  await valueRejected("policy-B-survives-restart", 9n);
  await confirmed(
    "failed-clear-policy-rolls-back",
    replacement,
    clear,
    "0x0",
    /unknown function selector/i,
    accountManagerAddress,
    true,
  );
  await valueRejected("policy-B-retained-after-failed-clear", 9n);
  await confirmed("clear-policy-restores-builtin", replacement, clear);
  await valueAllowed("builtin-allows-nine-after-clear", 9n);
  const finalState = await snapshot();
  for (const t of result.transactions.slice(customStart))
    assert.deepEqual(
      await rpc("debug_traceTransaction", [t.hash]),
      t.trace,
      t.label + " history",
    );
  assert.deepEqual(await snapshot(), finalState);
  await stop();
  await start(data, "cleared-policy-restart");
  assert.deepEqual(await snapshot(), finalState);
  await valueAllowed("builtin-after-clear-and-restart", 9n);
  result.customPolicySetReplaceClearRollbackVerified = true;
  result.finalHeight = height;
  result.passed = true;
} catch (e) {
  result.error = String(e);
  throw e;
} finally {
  await stop();
  result.nodeStopped = !node;
  result.endedAt = new Date().toISOString();
  await writeFile(join(out, "runtime.json"), JSON.stringify(result, null, 2));
  for (const signer of signers) signer.dispose();
  console.log(`Acceptance report: ${join(out, "runtime.json")}`);
}
