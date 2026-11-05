#!/usr/bin/env node
// Live physical checkpoint, ordinary restore and continued signed spending.
import assert from "node:assert/strict";
import {
  readFile,
  writeFile,
  mkdir,
  mkdtemp,
  cp,
  readdir,
  stat,
} from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes, createHash } from "node:crypto";
import { createServer } from "node:net";
import { spawn, spawnSync } from "node:child_process";
assert.ok(
  process.env.SHELL_SDK_ENTRY,
  "Set SHELL_SDK_ENTRY to a compatible built SDK dist/index.js",
);
const { createShellProvider, decryptKeystore, buildTransaction } = await import(
  pathToFileURL(resolve(process.env.SHELL_SDK_ENTRY))
);
const binary = resolve(process.env.NODE_BIN ?? "target/debug/shell-node");
const out = await mkdtemp(join(tmpdir(), "shell-native-backup-")),
  data = join(out, "source");
const result = {
  startedAt: new Date().toISOString(),
  commands: [],
  rpc: [],
  transactions: [],
  states: {},
  sourceFixture: process.env.SHELL_BACKUP_SOURCE_FIXTURE ?? null,
};
const save = () =>
  writeFile(join(out, "runtime.json"), JSON.stringify(result, null, 2));
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
let child, port, provider, signer;
const passwordPath = join(out, "password.txt"),
  keyPath = join(out, "validator.json"),
  apiKeyPath = join(out, "rpc-key.txt");
let apiKey;
function cli(args, label) {
  const p = spawnSync(binary, args, { encoding: "utf8" });
  result.commands.push({
    label,
    argv: args,
    exit_code: p.status,
    stdout: label === "keygen" ? "[key generation output omitted]" : p.stdout,
    stderr: p.stderr,
  });
  assert.equal(p.status, 0, p.stderr);
  return p.stdout;
}
async function unusedPort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
}
async function request(method, params = [], token = apiKey) {
  const body = { jsonrpc: "2.0", id: result.rpc.length + 1, method, params };
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const text = await r.text();
  let output;
  try {
    output = JSON.parse(text);
  } catch {
    output = { text };
  }
  result.rpc.push({ input: body, http: r.status, output });
  return { http: r.status, output };
}
async function rpc(method, params = []) {
  const r = await request(method, params);
  assert.equal(r.http, 200);
  if (r.output.error) throw Error(JSON.stringify(r.output.error));
  return r.output.result;
}
async function stop() {
  if (!child) return;
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
  result.commands.find((c) => c.pid === child.pid).exit = {
    code: child.exitCode,
    signal: child.signalCode,
  };
  child = null;
  await save();
}
// Keep service startup and the recorded process arguments together.
async function start(dir, label, admin = true) {
  assert.ok(!child);
  port = await unusedPort();
  const args = [
    "run",
    "--datadir",
    dir,
    "--keystore",
    keyPath,
    "--password-file",
    passwordPath,
    "--rpc-addr",
    `127.0.0.1:${port}`,
    "--metrics-addr",
    "127.0.0.1:0",
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
    "--rpc-api-key",
    apiKey,
  ];
  if (admin) args.push("--rpc-api", "eth,net,web3,shell,admin");
  const fd = openSync(join(out, label + ".log"), "w");
  child = spawn(binary, args, { stdio: ["ignore", fd, fd] });
  closeSync(fd);
  const publicArgs = [...args];
  publicArgs[publicArgs.indexOf("--rpc-api-key") + 1] = "[redacted]";
  result.commands.push({ label, pid: child.pid, argv: publicArgs });
  await save();
  for (let n = 0; n < 160; n++) {
    assert.equal(child.exitCode, null, "node exited");
    try {
      if ((await rpc("eth_chainId")) === "0x539") {
        provider = createShellProvider({
          rpcHttpUrl: `http://127.0.0.1:${port}`,
          rpcApiKey: apiKey,
        });
        return;
      }
    } catch {}
    await pause(250);
  }
  throw Error("RPC startup deadline");
}
async function confirm(hash) {
  const until = Date.now() + 90000;
  let receipt;
  while (!(receipt = await rpc("eth_getTransactionReceipt", [hash]))) {
    assert.ok(Date.now() < until, "signed transaction included");
    await pause(200);
  }
  assert.equal(receipt.status, "0x1");
  while (
    BigInt((await rpc("eth_getBlockByNumber", ["finalized", false])).number) <
    BigInt(receipt.blockNumber)
  ) {
    assert.ok(Date.now() < until, "signed transaction finalized");
    await pause(200);
  }
  return receipt;
}
async function send(value, label) {
  const nonce = Number(
    BigInt(
      await rpc("eth_getTransactionCount", [signer.getAddress(), "latest"]),
    ),
  );
  const signed = await signer.buildSignedTransaction({
    tx: buildTransaction({
      chainId: 1337,
      nonce,
      to: result.recipient,
      value: BigInt(value),
      data: "0x",
      gasLimit: 1000000,
    }),
    includePublicKey: true,
  });
  const hash = await provider.sendTransaction(signed);
  result.transactions.push({ label, hash, value, nonce });
  return hash;
}
async function capture(tag = "latest") {
  const block = await rpc("eth_getBlockByNumber", [tag, false]);
  return {
    block: Object.fromEntries(
      [
        "number",
        "hash",
        "parentHash",
        "stateRoot",
        "transactions",
        "timestamp",
        "gasUsed",
      ].map((key) => [key, block[key]]),
    ),
    nonce: await rpc("eth_getTransactionCount", [signer.getAddress(), tag]),
    senderBalance: await rpc("eth_getBalance", [signer.getAddress(), tag]),
    recipientBalance: await rpc("eth_getBalance", [result.recipient, tag]),
  };
}
async function manifest(dir, prefix = "") {
  const map = {};
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const key = join(prefix, e.name),
      p = join(dir, e.name);
    if (e.isDirectory()) Object.assign(map, await manifest(p, key));
    else if (e.isFile())
      map[key] = createHash("sha256")
        .update(await readFile(p))
        .digest("hex");
  }
  return map;
}
try {
  if (process.env.SHELL_BACKUP_SOURCE_FIXTURE) {
    const old = resolve(process.env.SHELL_BACKUP_SOURCE_FIXTURE);
    const previous = JSON.parse(
      await readFile(join(old, "runtime.json"), "utf8"),
    );
    assert.ok(previous.nodesStopped);
    assert.match(previous.error, /-32601/);
    await cp(join(old, "source"), data, { recursive: true });
    for (const name of ["password.txt", "validator.json", "rpc-key.txt"])
      await cp(join(old, name), join(out, name));
    result.recipient = previous.recipient;
    result.transactions = previous.transactions;
    result.states = previous.states;
  } else {
    await mkdir(data);
    await writeFile(passwordPath, randomBytes(24).toString("hex"), {
      mode: 0o600,
    });
    await writeFile(apiKeyPath, randomBytes(24).toString("hex"), {
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
        keyPath,
      ],
      "keygen",
    );
    result.recipient = "0x" + randomBytes(32).toString("hex");
  }
  const password = await readFile(passwordPath, "utf8");
  apiKey = await readFile(apiKeyPath, "utf8");
  signer = await decryptKeystore(
    JSON.parse(await readFile(keyPath, "utf8")),
    password,
  );
  result.sender = signer.getAddress();
  if (!process.env.SHELL_BACKUP_SOURCE_FIXTURE) {
    const genesis = {
      chain_id: 1337,
      chain_name: "live-checkpoint-acceptance",
      network_type: "Dev",
      timestamp: Math.floor(Date.now() / 1000) - 60,
      gas_limit: 30000000,
      extra_data: "live-checkpoint-acceptance",
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
    };
    await writeFile(
      join(data, "genesis.json"),
      JSON.stringify(genesis, null, 2),
    );
    await start(data, "default-namespace", false);
    assert.equal(
      (await request("admin_createSnapshot")).output.error?.code,
      -32601,
    );
    const hash = await send(7, "before checkpoint");
    result.transactions.at(-1).receipt = await confirm(hash);
    result.states["0x1"] = await capture("0x1");
    assert.equal(result.states["0x1"].recipientBalance, "0x7");
    await stop();
  }
  await start(data, "live-admin");
  console.log(`Acceptance artifacts: ${out}`);
  result.before = await capture();
  await save();
  assert.equal((await rpc("admin_nodeInfo")).chainId, 1337);
  const first = await rpc("admin_createSnapshot");
  assert.ok(first.backupPath, "real checkpoint path");
  const root = join(data, "backups");
  assert.ok(resolve(first.backupPath).startsWith(resolve(root) + "/"));
  const firstManifest = await manifest(first.backupPath);
  result.firstCheckpoint = first;
  await save();
  const authBefore = await readdir(root);
  assert.equal(
    (await request("admin_createSnapshot", [], "wrong-key")).http,
    401,
  );
  assert.equal((await request("admin_createSnapshot", [], null)).http, 401);
  assert.deepEqual(await readdir(root), authBefore);
  assert.equal(
    (await request("admin_createSnapshot", [join(out, "caller-selected")]))
      .output.error?.code,
    -32602,
  );
  assert.deepEqual(await readdir(root), authBefore);
  await assert.rejects(stat(join(out, "caller-selected")), { code: "ENOENT" });
  const secondHash = await send(11, "concurrent with checkpoint");
  const second = await rpc("admin_createSnapshot");
  assert.notEqual(second.backupPath, first.backupPath);
  result.secondCheckpoint = second;
  result.transactions.at(-1).receipt = await confirm(secondHash);
  result.states["0x2"] = await capture("0x2");
  const laterHash = await send(13, "after checkpoint");
  result.transactions.at(-1).receipt = await confirm(laterHash);
  result.states["0x3"] = await capture("0x3");
  assert.equal(result.states["0x3"].recipientBalance, "0x1f");
  assert.deepEqual(await manifest(first.backupPath), firstManifest);
  result.sourceFinal = await capture();
  await stop();
  const sourceManifest = await manifest(data);
  const trustedGenesis = await readFile(join(data, "genesis.json"));
  for (const [index, backup] of [first, second].entries()) {
    const restore = join(out, `restored-${index}`);
    await mkdir(restore);
    await writeFile(join(restore, "genesis.json"), trustedGenesis);
    cli(
      ["--datadir", restore, "backup", "restore", backup.backupPath],
      `restore-${index}`,
    );
    await start(restore, `restored-${index}`);
    const current = await capture();
    const finalized = await rpc("eth_getBlockByNumber", ["finalized", false]);
    assert.equal(finalized.number, current.block.number);
    assert.equal(finalized.hash, current.block.hash);
    result[`restored${index}Finalized`] = {
      number: finalized.number,
      hash: finalized.hash,
    };
    const height = Number(BigInt(current.block.number));
    assert.ok(index === 0 ? height === 1 : height === 1 || height === 2);
    const expected = result.states[current.block.number];
    assert.deepEqual(
      current,
      expected,
      "actual restored canonical state equals independent source point",
    );
    assert.equal(await rpc("eth_getTransactionReceipt", [laterHash]), null);
    const firstReceipt = await rpc("eth_getTransactionReceipt", [
      result.transactions[0].hash,
    ]);
    assert.deepEqual(firstReceipt, result.transactions[0].receipt);
    result[`restored${index}`] = current;
    if (index === 1) {
      const spendHash = await send(17, "new spending after restore");
      const receipt = await confirm(spendHash);
      result.transactions.at(-1).receipt = receipt;
      const spent = await capture();
      assert.equal(
        BigInt(spent.recipientBalance),
        BigInt(current.recipientBalance) + 17n,
      );
      assert.equal(BigInt(spent.nonce), BigInt(current.nonce) + 1n);
      await stop();
      await start(restore, "restored-reopen");
      assert.deepEqual(await capture(), spent);
      const finalizedReopen = await rpc("eth_getBlockByNumber", [
        "finalized",
        false,
      ]);
      assert.equal(finalizedReopen.hash, spent.block.hash);
      result.finalizedAfterSpendingReopen = {
        number: finalizedReopen.number,
        hash: finalizedReopen.hash,
      };
      assert.deepEqual(
        await rpc("eth_getTransactionReceipt", [spendHash]),
        receipt,
      );
      result.afterSpendingReopen = spent;
    }
    await stop();
  }
  assert.deepEqual(
    await manifest(data),
    sourceManifest,
    "restoration never changes source database",
  );
  result.passed = true;
} catch (error) {
  result.error = String(error);
  process.exitCode = 1;
} finally {
  await stop();
  result.nodesStopped = !child;
  result.endedAt = new Date().toISOString();
  await save();
  signer?.dispose();
  console.log(`Acceptance report: ${join(out, "runtime.json")}`);
}
