#!/usr/bin/env node
// Verified native HTTPS/WSS, signed subscriptions and physical reopen.
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir, mkdtemp, cp } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { randomBytes, createHash } from "node:crypto";
import { createServer, connect } from "node:net";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { spawn, spawnSync } from "node:child_process";

assert.ok(
  process.env.SHELL_SDK_ENTRY,
  "Set SHELL_SDK_ENTRY to a compatible built SDK dist/index.js",
);
const binary = resolve(process.env.NODE_BIN ?? "target/debug/shell-node");
const worker = process.argv[2] === "--worker";
const out = worker
  ? resolve(process.argv[3])
  : await mkdtemp(join(tmpdir(), "shell-native-tls-"));
const certPath = join(out, "cert.pem"),
  tlsKeyPath = join(out, "tls-key.pem");
if (!worker) {
  const args = [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-out",
    certPath,
    "-keyout",
    tlsKeyPath,
  ];
  const cert = spawnSync("openssl", args, { encoding: "utf8" });
  await writeFile(
    join(out, "bootstrap.json"),
    JSON.stringify(
      {
        args,
        exit_code: cert.status,
        stdout: cert.stdout,
        stderr: cert.stderr,
      },
      null,
      2,
    ),
  );
  assert.equal(cert.status, 0, cert.stderr);
  const child = spawn(
    process.execPath,
    [fileURLToPath(import.meta.url), "--worker", out],
    {
      stdio: "inherit",
      env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath },
    },
  );
  const exit = await new Promise((r) =>
    child.once("exit", (code, signal) => r({ code, signal })),
  );
  await writeFile(
    join(out, "worker-exit.json"),
    JSON.stringify({ pid: child.pid, ...exit }, null, 2),
  );
  process.exitCode = exit.code ?? 1;
} else {
  const entry = resolve(process.env.SHELL_SDK_ENTRY);
  const { createShellProvider, decryptKeystore, buildTransaction } =
    await import(pathToFileURL(entry));
  const require = createRequire(entry);
  const { WebSocket } = require("ws");
  const certificate = await readFile(certPath);
  const data = join(out, "source"),
    keyPath = join(out, "validator.json"),
    passwordPath = join(out, "password.txt");
  const apiKey = randomBytes(24).toString("hex");
  const result = {
    startedAt: new Date().toISOString(),
    commands: [],
    rpc: [],
    ws: [],
    negative: [],
    transactions: [],
    wsVersion: require("ws/package.json").version,
    binarySha256: createHash("sha256")
      .update(await readFile(binary))
      .digest("hex"),
    sdkEntrySha256: createHash("sha256")
      .update(await readFile(entry))
      .digest("hex"),
  };
  const save = () =>
    writeFile(join(out, "runtime.json"), JSON.stringify(result, null, 2));
  const pause = (ms) => new Promise((r) => setTimeout(r, ms));
  let child,
    signer,
    port,
    wsPort,
    provider,
    socket,
    nextId = 1;
  const pending = new Map();
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
    const server = createServer();
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const value = server.address().port;
    await new Promise((r) => server.close(r));
    return value;
  }
  function request(method, params = [], options = {}) {
    const input = { jsonrpc: "2.0", id: nextId++, method, params };
    const token = Object.hasOwn(options, "token") ? options.token : apiKey;
    return new Promise((resolve_, reject) => {
      const req = httpsRequest(
        {
          host: "127.0.0.1",
          port,
          method: "POST",
          path: "/",
          ca: certificate,
          headers: {
            "content-type": "application/json",
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
          ...options,
        },
        (res) => {
          let text = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => (text += chunk));
          res.on("end", () => {
            let output;
            try {
              output = JSON.parse(text);
            } catch {
              output = { text };
            }
            result.rpc.push({ input, http: res.statusCode, output });
            resolve_({ http: res.statusCode, output });
          });
        },
      );
      req.setTimeout(5000, () =>
        req.destroy(new Error("HTTPS request timeout")),
      );
      req.on("error", reject);
      req.end(JSON.stringify(input));
    });
  }
  async function rpc(method, params = []) {
    const response = await request(method, params);
    assert.equal(response.http, 200);
    assert.ok(!response.output.error, JSON.stringify(response.output.error));
    return response.output.result;
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
  async function start(label) {
    assert.ok(!child);
    port = await unusedPort();
    wsPort = await unusedPort();
    const args = [
      "run",
      "--datadir",
      data,
      "--keystore",
      keyPath,
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
      `127.0.0.1:${port}`,
      "--metrics-addr",
      "127.0.0.1:0",
      "--rpc-tls-cert",
      certPath,
      "--rpc-tls-key",
      tlsKeyPath,
      "--rpc-api-key",
      apiKey,
      "--ws",
      "--ws-port",
      String(wsPort),
    ];
    const fd = openSync(join(out, label + ".log"), "w");
    child = spawn(binary, args, { stdio: ["ignore", fd, fd] });
    closeSync(fd);
    const publicArgs = [...args];
    publicArgs[publicArgs.indexOf("--rpc-api-key") + 1] = "[redacted]";
    result.commands.push({ label, argv: publicArgs, pid: child.pid });
    await save();
    for (let n = 0; n < 120; n++) {
      assert.equal(child.exitCode, null, "node exited before TLS startup");
      try {
        if ((await rpc("eth_chainId")) === "0x539") {
          provider = createShellProvider({
            rpcHttpUrl: `https://127.0.0.1:${port}`,
            rpcApiKey: apiKey,
          });
          return;
        }
      } catch {}
      await pause(250);
    }
    throw Error("Native TLS startup timeout");
  }
  async function state() {
    const block = await rpc("eth_getBlockByNumber", ["latest", false]);
    const finalized = await rpc("eth_getBlockByNumber", ["finalized", false]);
    return {
      block: Object.fromEntries(
        [
          "number",
          "hash",
          "parentHash",
          "stateRoot",
          "transactions",
          "timestamp",
        ].map((k) => [k, block[k]]),
      ),
      finalized: { number: finalized.number, hash: finalized.hash },
      senderBalance: await rpc("eth_getBalance", [
        signer.getAddress(),
        "latest",
      ]),
      nonce: await rpc("eth_getTransactionCount", [
        signer.getAddress(),
        "latest",
      ]),
      recipientBalance: await rpc("eth_getBalance", [
        result.recipient,
        "latest",
      ]),
    };
  }
  async function confirm(hash) {
    const until = Date.now() + 90000;
    let receipt;
    while (!(receipt = await rpc("eth_getTransactionReceipt", [hash]))) {
      assert.ok(Date.now() < until);
      await pause(200);
    }
    assert.equal(receipt.status, "0x1");
    while (
      BigInt((await rpc("eth_getBlockByNumber", ["finalized", false])).number) <
      BigInt(receipt.blockNumber)
    ) {
      assert.ok(Date.now() < until);
      await pause(200);
    }
    return receipt;
  }
  async function send(value) {
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
    const receipt = await confirm(hash);
    result.transactions.push({ hash, value, nonce, receipt });
    return receipt;
  }
  async function expectTlsFailure(label, options, code) {
    try {
      await request("eth_chainId", [], options);
      assert.fail(label + " unexpectedly accepted");
    } catch (error) {
      assert.equal(error.code, code);
      result.negative.push({ label, code: error.code });
    }
  }
  async function expectWsRejected(label, token) {
    await new Promise((resolve_, reject) => {
      const ws = new WebSocket(`wss://127.0.0.1:${port}`, {
        handshakeTimeout: 5000,
        ca: certificate,
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });
      const timer = setTimeout(() => {
        ws.terminate();
        reject(Error("WSS rejection timeout"));
      }, 5000);
      ws.once("open", () => {
        clearTimeout(timer);
        ws.close();
        reject(Error(label + " unexpectedly upgraded"));
      });
      ws.once("unexpected-response", (_req, response) => {
        response.resume();
        clearTimeout(timer);
        ws.terminate();
        if (response.statusCode !== 401) {
          reject(
            Error(`${label}: expected HTTP 401, got ${response.statusCode}`),
          );
          return;
        }
        result.negative.push({ label, http: response.statusCode });
        resolve_();
      });
      ws.on("error", () => {});
    });
  }
  async function connectWs() {
    socket = new WebSocket(`wss://127.0.0.1:${port}`, {
      handshakeTimeout: 5000,
      ca: certificate,
      headers: { authorization: `Bearer ${apiKey}` },
    });
    socket.on("message", (data_) => {
      try {
        const message = JSON.parse(data_.toString());
        result.ws.push(message);
        if (pending.has(message.id)) {
          const waiter = pending.get(message.id);
          pending.delete(message.id);
          waiter(message);
        }
      } catch (error) {
        result.transportError = String(error);
        socket?.terminate();
      }
    });
    socket.on("error", () => {});
    await new Promise((resolve_, reject) => {
      socket.once("open", resolve_);
      socket.once("error", reject);
    });
  }
  async function closeWs() {
    if (!socket) return;
    const current = socket;
    socket = null;
    if (current.readyState === WebSocket.CLOSED) return;
    await new Promise((resolve_) => {
      const timer = setTimeout(() => {
        current.terminate();
        resolve_();
      }, 2000);
      current.once("close", () => {
        clearTimeout(timer);
        resolve_();
      });
      current.close();
    });
  }
  async function wsRpc(method, params = []) {
    const id = nextId++;
    const response = await new Promise((resolve_, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(Error("WSS RPC timeout: " + method));
      }, 5000);
      pending.set(id, (value) => {
        clearTimeout(timer);
        resolve_(value);
      });
      socket.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
    assert.ok(!response.error, JSON.stringify(response.error));
    return response.result;
  }
  try {
    const old = process.env.SHELL_TLS_SOURCE_FIXTURE;
    if (old) {
      const prior = JSON.parse(
        await readFile(join(old, "runtime.json"), "utf8"),
      );
      assert.ok(prior.nodesStopped);
      await cp(join(old, "source"), data, { recursive: true });
      for (const [from, to] of [
        ["validator.json", keyPath],
        ["password.txt", passwordPath],
      ])
        await cp(join(old, from), to);
      result.recipient = prior.recipient;
      result.reusedBaseline = prior.states["0x1"];
    } else {
      await mkdir(data);
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
          keyPath,
        ],
        "keygen",
      );
      result.recipient = "0x" + randomBytes(32).toString("hex");
    }
    signer = await decryptKeystore(
      JSON.parse(await readFile(keyPath, "utf8")),
      await readFile(passwordPath, "utf8"),
    );
    if (!old) {
      await writeFile(
        join(data, "genesis.json"),
        JSON.stringify(
          {
            chain_id: 1337,
            chain_name: "native-tls-acceptance",
            network_type: "Dev",
            timestamp: Math.floor(Date.now() / 1000) - 60,
            gas_limit: 30000000,
            extra_data: "native-tls-acceptance",
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
    await start("tls-initial");
    console.log(`Acceptance artifacts: ${out}`);
    result.before = await state();
    await save();
    if (old) {
      assert.equal(result.before.block.hash, result.reusedBaseline.block.hash);
      assert.equal(
        result.before.recipientBalance,
        result.reusedBaseline.recipientBalance,
      );
    }
    await expectTlsFailure(
      "untrusted certificate",
      { ca: [] },
      "DEPTH_ZERO_SELF_SIGNED_CERT",
    );
    await expectTlsFailure(
      "wrong hostname",
      { servername: "wrong.invalid" },
      "ERR_TLS_CERT_ALTNAME_INVALID",
    );
    for (const token of [null, "wrong-key"])
      assert.equal((await request("eth_chainId", [], { token })).http, 401);
    await expectWsRejected("missing WSS API key", null);
    await expectWsRejected("wrong WSS API key", "wrong-key");
    result.separateWsPort = await new Promise((resolve_) => {
      const connection = connect({ host: "127.0.0.1", port: wsPort });
      connection.once("connect", () => {
        connection.destroy();
        resolve_({ connected: true });
      });
      connection.once("error", (error) =>
        resolve_({ connected: false, code: error.code }),
      );
    });
    assert.equal(
      result.separateWsPort.connected,
      false,
      "TLS must not leave an unprotected separate WS listener",
    );
    result.plainHttpOnTls = await new Promise((resolve_) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method: "POST",
          headers: { "content-type": "application/json" },
        },
        (response) => {
          let body = "";
          response.on("data", (chunk) => (body += chunk));
          response.on("end", () =>
            resolve_({ http: response.statusCode, body }),
          );
        },
      );
      req.setTimeout(2000, () => req.destroy(new Error("plaintext timeout")));
      req.on("error", (error) =>
        resolve_({ error: error.code ?? error.message }),
      );
      req.end('{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}');
    });
    assert.ok(!result.plainHttpOnTls.body?.includes("0x539"));
    assert.deepEqual(
      await state(),
      result.before,
      "rejections leave account and canonical state unchanged",
    );
    await connectWs();
    assert.equal(await wsRpc("eth_chainId"), "0x539");
    const subscription = await wsRpc("eth_subscribe", ["newHeads"]);
    result.subscription = subscription;
    const first = await send(19);
    const until = Date.now() + 5000;
    let event;
    while (
      !(event = result.ws.find(
        (v) =>
          v.params?.subscription === subscription &&
          v.params.result?.hash === first.blockHash,
      ))
    ) {
      assert.ok(Date.now() < until, "genuine TLS newHeads received");
      await pause(25);
    }
    const header = await rpc("eth_getBlockByNumber", [
      first.blockNumber,
      false,
    ]);
    for (const name of ["hash", "number", "parentHash", "stateRoot"])
      assert.equal(event.params.result[name], header[name]);
    assert.equal(await wsRpc("eth_unsubscribe", [subscription]), true);
    const canceledAt = result.ws.length;
    const second = await send(23);
    await pause(300);
    assert.equal(await wsRpc("eth_blockNumber"), second.blockNumber);
    assert.ok(
      !result.ws
        .slice(canceledAt)
        .some((v) => v.params?.subscription === subscription),
    );
    result.after = await state();
    assert.equal(
      BigInt(result.after.recipientBalance),
      BigInt(result.before.recipientBalance) + 42n,
    );
    assert.equal(BigInt(result.after.nonce), BigInt(result.before.nonce) + 2n);
    assert.equal(result.after.finalized.hash, second.blockHash);
    await closeWs();
    await stop();
    await start("tls-reopen");
    assert.deepEqual(await state(), result.after);
    for (const tx of result.transactions)
      assert.deepEqual(
        await rpc("eth_getTransactionReceipt", [tx.hash]),
        tx.receipt,
      );
    await connectWs();
    assert.deepEqual(
      await wsRpc("eth_getTransactionReceipt", [first.transactionHash]),
      first,
    );
    await closeWs();
    assert.equal(result.transportError, undefined);
    result.passed = true;
  } catch (error) {
    result.error = String(error);
    process.exitCode = 1;
  } finally {
    await closeWs();
    await stop();
    result.nodesStopped = !child;
    result.endedAt = new Date().toISOString();
    await save();
    signer?.dispose();
    console.log(`Acceptance report: ${join(out, "runtime.json")}`);
  }
}
