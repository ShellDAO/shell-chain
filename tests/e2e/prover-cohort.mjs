import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createServer } from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
assert.ok(process.env.SHELL_NODE_BIN && process.env.SHELL_SDK_ENTRY, 'Set SHELL_NODE_BIN and SHELL_SDK_ENTRY to compatible node and SDK builds');
const root = await mkdtemp(join(tmpdir(), 'shell-prover-cohort-'));
const out = join(root, 'runtime');
await mkdir(out, {
    recursive: true, mode: 0o700
});
const binary = resolve(process.env.SHELL_NODE_BIN);
const sdk = resolve(process.env.SHELL_SDK_ENTRY);
const { ShellSigner, MlDsa65Adapter, buildTransaction, createShellProvider } = await import(pathToFileURL(sdk).href);
const sender = new ShellSigner('MlDsa65', MlDsa65Adapter.generate());
const password = join(out, 'password');
await writeFile(password, randomBytes(24).toString('hex'), {
    mode: 0o600
});
const result = {
    runtime: root, binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), startedAt: new Date().toISOString(), binary, sdk, adaptation: 'Explicit static worker cohort, isolated registry activation0 and 512 genuine transfers. Does not qualify dynamic membership or failover.', commands: [], receipts: [], nodesStopped: false
};
const save = () => writeFile(join(root, 'runtime-result.json'), JSON.stringify(result, null, 2));
const pause = ms => new Promise(r => setTimeout(r, ms));
const nodes = [];
const ports = [], p2p = [], metrics = [];
const keys = [];
async function port() {
    const s = createServer();
    await new Promise((r, j) => {
        s.once('error', j);
        s.listen(0, '127.0.0.1', r);
    });
    const p = s.address().port;
    await new Promise(r => s.close(r));
    return p;
}
function cli(label, args) {
    const q = spawnSync(binary, args, {
        encoding: 'utf8'
    });
    result.commands.push({
        label, args, status: q.status
    });
    assert.equal(q.status, 0, q.stderr);
    return q.stdout;
}
let sequence = Promise.resolve();
function paced(f) {
    const p = sequence.then(() => pause(50)).then(f);
    sequence = p.catch(() => {
    });
    return p;
}
async function rpc(i, method, params = []) {
    return paced(async () => {
        const r = await fetch(`http://127.0.0.1:${ports[i]}`, {
            method: 'POST', headers: {
                'content-type': 'application/json'
            }, body: JSON.stringify({
                jsonrpc: '2.0', id: 1, method, params
            }), signal: AbortSignal.timeout(10000)
        });
        const x = await r.json();
        assert.ok(!x.error, JSON.stringify(x.error));
        return x.result;
    });
}
async function until(f, seconds = 60) {
    const end = Date.now() + seconds * 1000;
    while (Date.now() < end) {
        for (const n of nodes)
            if (n)
                assert.equal(n.exitCode, null, 'native process exited');
        try {
            const v = await f();
            if (v)
                return v;
        }
        catch (e) {
            if (e.name !== 'TypeError' && ![
                'ECONNREFUSED', 'UND_ERR_SOCKET'
            ].includes(e.cause?.code))
                throw e;
        }
        await pause(150);
    }
    throw Error('acceptance predicate timeout');
}
async function stopAll() {
    for (const n of nodes) {
        if (n && n.exitCode === null && n.signalCode === null) {
            n.kill('SIGTERM');
            await Promise.race([
                new Promise(r => n.once('exit', r)), pause(20000)
            ]);
            if (n.exitCode === null && n.signalCode === null) {
                n.kill('SIGKILL');
                await new Promise(r => n.once('exit', r));
            }
        }
    }
    result.stops ??= [];
    result.stops.push(nodes.filter(Boolean).map(n => ({
        pid: n.pid, code: n.exitCode, signal: n.signalCode
    })));
    nodes.fill(undefined);
    result.nodesStopped = true;
}
for (const sig of [
    'SIGINT', 'SIGTERM'
])
    process.once(sig, () => stopAll().then(save).then(() => process.exit(1)));
async function start(i, boot) {
    result.nodesStopped = false;
    const args = [
        '--password-file', password, 'run', '--keystore', join(out, `key${i}.json`), '--config', join(out, `node${i}.toml`), '--datadir', join(out, `db${i}`), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb', '--rpc-addr', `127.0.0.1:${ports[i]}`, '--metrics-addr', `127.0.0.1:${metrics[i]}`, '--p2p', '--p2p-addr', `127.0.0.1:${p2p[i]}`, '--node-role', i === 0 ? 'validator' : 'prover', '--enable-stark-aggregation', '--consensus-engine', 'wpoa', '--block-time', '1000', '--max-idle-interval', '0', '--log-level', 'info'
    ];
    if (boot)
        args.push('--bootnode', boot);
    const fd = openSync(join(out, `node${i}.log`), 'w');
    const n = spawn(binary, args, {
        stdio: [
            'ignore', fd, fd
        ], env: {
            ...process.env, RUST_LOG: 'info'
        }
    });
    closeSync(fd);
    nodes[i] = n;
    result.commands.push({
        label: `start${i}`, args, pid: n.pid
    });
    await save();
    await until(() => rpc(i, 'eth_blockNumber'), 30);
}
async function metricText(i) {
    return (await fetch(`http://127.0.0.1:${metrics[i]}/metrics`, {
        signal: AbortSignal.timeout(10000)
    })).text();
}
function count(text) {
    const m = text.match(/^shell_stark_proofs_generated_total (\S+)$/m);
    assert.ok(m, 'generated metric present');
    return Number(m[1]);
}
try {
    result.binaryVersion = cli('version', [
        '--version'
    ]).trim();
    for (let i = 0; i < 3; i++) {
        ports[i] = await port();
        p2p[i] = await port();
        metrics[i] = await port();
        cli(`key${i}`, [
            '--password-file', password, 'key', 'generate', '--algorithm', 'mldsa65', '--output', join(out, `key${i}.json`)
        ]);
        keys[i] = JSON.parse(await readFile(join(out, `key${i}.json`), 'utf8'));
        await writeFile(join(out, `node${i}.toml`), '[network]\nenable_mdns=false\n[prover]\nproving_priority="sequential"\n');
    }
    result.ports = {
        rpc: ports, p2p, metrics
    };
    result.addresses = keys.map(k => k.address);
    assert.equal(new Set(result.addresses).size, 3);
    const genesis = {
        prover_registry_height: 0, chain_id: 1337, chain_name: 'multiple-provers', network_type: 'Dev', timestamp: Math.floor(Date.now() / 1000), gas_limit: 30000000, extra_data: 'multiple-provers', consensus: {
            engine: 'wpoa', authorities: [
                keys[0].address
            ], authority_pubkeys: [
                '0x' + keys[0].public_key.replace(/^0x/, '')
            ], weights: [
                1
            ], block_time_secs: 1, max_future_secs: 60, epoch_length: 0
        }, alloc: {
            [sender.getAddress()]: {
                balance: '0x3635c9adc5dea00000'
            }, [keys[0].address]: {
                balance: '0x3635c9adc5dea00000'
            }
        }, boot_nodes: []
    };
    await writeFile(join(out, 'genesis.json'), JSON.stringify(genesis));
    for (let i = 0; i < 3; i++)
        cli(`init${i}`, [
            '--datadir', join(out, `db${i}`), 'init', '--genesis', join(out, 'genesis.json'), '--chain-id', '1337', '--network', 'dev'
        ]);
    await start(0);
    const validators = await rpc(0, 'shell_getValidators');
    result.validatorsBefore = validators;
    for (let i = 1; i < 3; i++) {
        const hash = await rpc(0, 'shell_proposeRegisterProver', [
            keys[i].public_key, 1
        ]);
        const receipt = await until(() => rpc(0, 'eth_getTransactionReceipt', [
            hash
        ]));
        assert.equal(receipt.status, '0x1');
        const rec = await rpc(0, 'shell_getRegisteredProver', [
            keys[i].address
        ]);
        assert.ok(rec);
        result[`registration${i}`] = {
            hash, receipt, record: rec
        };
    }
    assert.deepEqual(await rpc(0, 'shell_getValidators'), validators);
    const log = await readFile(join(out, 'node0.log'), 'utf8');
    const boot = log.match(/\/ip4\/127\.0\.0\.1\/tcp\/\d+\/p2p\/[A-Za-z0-9]+/g)?.at(-1);
    assert.ok(boot, 'actual advertised bootstrap address');
    for (let i = 1; i < 3; i++)
        await writeFile(join(out, `node${i}.toml`), '[network]\nenable_mdns=false\n[prover]\nproving_priority="sequential"\nworker_cohort=' + JSON.stringify(keys.slice(1).map(k => k.address)) + '\n');
    await start(1, boot);
    await start(2, boot);
    for (let i = 1; i < 3; i++) {
        await until(async () => Number(BigInt(await rpc(i, 'net_peerCount'))) > 0 && !!(await rpc(i, 'shell_getRegisteredProver', [
            keys[2].address
        ])));
        assert.equal(count(await metricText(i)), 0);
    }
    result.connectedBeforeWindow = await Promise.all([
        0, 1, 2
    ].map(i => rpc(i, 'shell_getNodeInfo')));
    await save();
    const provider = createShellProvider({
        rpcHttpUrl: `http://127.0.0.1:${ports[0]}`
    });
    const recipient = '0x' + 'ab'.repeat(32);
    const signed = [];
    for (let nonce = 0; nonce < 512; nonce++)
        signed.push(await sender.buildSignedTransaction({
            tx: buildTransaction({
                chainId: 1337, nonce, to: recipient, value: 1n, gasLimit: 21000
            }), includePublicKey: true
        }));
    for (let offset = 0; offset < 512; offset += 16) {
        const hashes = [];
        for (const tx of signed.slice(offset, offset + 16))
            hashes.push(await paced(() => provider.sendTransaction(tx)));
        for (const h of hashes) {
            const receipt = await until(() => rpc(0, 'eth_getTransactionReceipt', [
                h
            ]));
            assert.equal(receipt.status, '0x1');
            result.receipts.push(receipt);
        }
        result.accepted = result.receipts.length;
        await save();
        console.log('accepted', result.accepted);
    }
    assert.equal(BigInt(await rpc(0, 'eth_getBalance', [
        recipient, 'latest'
    ])), 512n);
    result.recipientBalance = '512';
    assert.deepEqual(await rpc(0, 'shell_getValidators'), validators);
    await until(async () => count(await metricText(1)) + count(await metricText(2)) >= 1, 90);
    await pause(5000);
    result.workers = [];
    for (let i = 1; i < 3; i++) {
        const text = await metricText(i);
        await writeFile(join(out, `metrics${i}.txt`), text);
        const log = await readFile(join(out, `node${i}.log`), 'utf8');
        const relevant = log.split('\n').filter(s => /ProverService: (proving|proof amendment stored|proof generation)|proof task panicked/.test(s));
        result.workers.push({
            i, address: keys[i].address, generated: count(text), generationLogs: relevant, record: await rpc(0, 'shell_getRegisteredProver', [
                keys[i].address
            ])
        });
    }
    result.sourceBlocks = [
        ...new Set(result.receipts.map(x => x.blockHash))
    ];
    result.finalized = await rpc(0, 'eth_getBlockByNumber', [
        'finalized', false
    ]);
    const total = result.workers.reduce((n, w) => n + w.generated, 0);
    assert.equal(total, 1, 'the one qualifying canonical window must have one generated proof across the cohort');
    const last = result.receipts.at(-1);
    await until(async () => {
        const f = await rpc(0, 'eth_getBlockByNumber', [
            'finalized', false
        ]);
        return BigInt(f.number) >= BigInt(last.blockNumber);
    });
    await until(async () => {
        const counts = await Promise.all([
            1, 2
        ].map(i => rpc(0, 'shell_getRegisteredProver', [
            keys[i].address
        ])));
        return counts.reduce((n, x) => n + x.proofs_submitted, 0) === 1;
    });
    for (let i = 1; i < 3; i++)
        await until(async () => {
            const f = await rpc(i, 'eth_getTransactionReceipt', [
                last.transactionHash
            ]);
            return f?.status === '0x1' && BigInt(await rpc(i, 'eth_getBalance', [
                recipient, 'latest'
            ])) === 512n;
        });
    await stopAll();
    await save();
    // Reopening the same database with a different membership must fail before
    // listeners or proof work start; restoring the original config must recover.
    const cfg = join(out, 'node1.toml');
    const original = await readFile(cfg, 'utf8');
    await writeFile(cfg, '[prover]\nworker_cohort=' + JSON.stringify([
        keys[1].address
    ]) + '\n');
    const wrong = spawnSync(binary, result.commands.find(c => c.label === 'start1').args, {
        encoding: 'utf8', timeout: 30000
    });
    await writeFile(join(out, 'changed-cohort.log'), wrong.stdout + wrong.stderr);
    assert.notEqual(wrong.status, 0);
    assert.match(wrong.stdout + wrong.stderr, /persisted assignment/);
    result.changedCohortRejected = {
        status: wrong.status
    };
    await writeFile(cfg, original);
    await start(0);
    await start(1, boot);
    await start(2, boot);
    for (let i = 0; i < 3; i++) {
        assert.equal(BigInt(await rpc(i, 'eth_getBalance', [
            recipient, 'latest'
        ])), 512n);
        assert.equal(BigInt(await rpc(i, 'eth_getTransactionCount', [
            sender.getAddress(), 'latest'
        ])), 512n);
        assert.equal((await rpc(i, 'eth_getTransactionReceipt', [
            last.transactionHash
        ])).status, '0x1');
    }
    await pause(1500);
    for (let i = 1; i < 3; i++)
        assert.equal(count(await metricText(i)), 0, 'persisted proofs must not be recomputed after all native nodes restart');
    result.reopenPassed = true;
    result.status = 'PASS: one actual proof, unchanged validators, genuine receipts/state and all three native RocksDB reopens';
    await save();
    console.log(JSON.stringify({
        runtime: root, workers: result.workers.map(w => ({
            i: w.i, generated: w.generated, logs: w.generationLogs
        })), status: result.status
    }));
}
catch (e) {
    result.error = e.stack;
    console.error(e.stack);
    process.exitCode = 1;
}
finally {
    await stopAll();
    result.endedAt = new Date().toISOString();
    await save();
}
