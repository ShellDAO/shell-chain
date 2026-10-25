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
const lateJoin = process.env.SHELL_COHORT_LATE_JOIN === '1';
const reconfigure = lateJoin || process.env.SHELL_COHORT_RECONFIGURE === '1';
const nodeCount = lateJoin ? 4 : 3;
const workers = Array.from({ length: nodeCount - 1 }, (_, i) => i + 1);
const logPhases = Array(nodeCount).fill(0);
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
    if (logPhases[i]++) {
        await writeFile(join(out, `node${i}.before-reopen-${logPhases[i]}.log`), await readFile(join(out, `node${i}.log`)));
    }
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
    for (let i = 0; i < nodeCount; i++) {
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
    assert.equal(new Set(result.addresses).size, nodeCount);
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
    for (let i = 0; i < nodeCount; i++)
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
        await writeFile(join(out, `node${i}.toml`), '[network]\nenable_mdns=false\n[prover]\nproving_priority="sequential"\nworker_cohort=' + JSON.stringify(keys.slice(1, 3).map(k => k.address)) + '\n');
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
    if (reconfigure) {
        if (lateJoin) {
            const hash = await rpc(0, 'shell_proposeRegisterProver', [keys[3].public_key, 1]);
            const receipt = await until(() => rpc(0, 'eth_getTransactionReceipt', [hash]));
            assert.equal(receipt.status, '0x1');
            const record = await rpc(0, 'shell_getRegisteredProver', [keys[3].address]);
            assert.ok(record);
            assert.equal(record.proofs_submitted, 0);
            assert.deepEqual(await rpc(0, 'shell_getValidators'), validators);
            result.registration3 = { hash, receipt, record };
        }
        // Choose different old/new owners for the crossing range, so selecting
        // membership by its end height would actually fail this native check.
        const firstEnd = Number(result.workers.flatMap(w => w.generationLogs).join('\n').match(/range ending at block #(\d+)/)[1]);
        const crossingStart = firstEnd + 1;
        const firstSource = await rpc(0, 'eth_getBlockByNumber', ['0x' + crossingStart.toString(16), false]);
        assert.ok(firstSource?.hash);
        const sorted = keys.slice(1, 3).map(k => k.address.toLowerCase()).sort();
        const oldOwner = sorted[Number(BigInt('0x' + firstSource.hash.slice(2, 18)) % 2n)];
        const crossingWorker = keys.findIndex(k => k.address.toLowerCase() === oldOwner);
        const target = lateJoin ? 3 : 3 - crossingWorker;
        const heads = await Promise.all([0, 1, 2].map(i => rpc(i, 'eth_blockNumber')));
        const fromBlock = Math.max(...heads.map(h => Number(BigInt(h)))) + 2;
        await stopAll();
        const base = '[network]\nenable_mdns=false\n[prover]\nproving_priority="sequential"\nworker_cohort=' + JSON.stringify(keys.slice(1, 3).map(k => k.address)) + '\n';
        const scheduled = height => base + '[[prover.worker_cohort_schedule]]\nfrom_block=' + height + '\nworkers=' + JSON.stringify([keys[target].address]) + '\n';
        const failStart = async (name, config, pattern) => {
            await writeFile(cfg, config);
            const failed = spawnSync(binary, result.commands.find(c => c.label === 'start1').args, { encoding: 'utf8', timeout: 30000 });
            await writeFile(join(out, name + '.log'), failed.stdout + failed.stderr);
            assert.equal(failed.status, 1, name);
            assert.match(failed.stdout + failed.stderr, pattern);
            result[name] = { status: failed.status };
        };
        await failStart('backdated-schedule', scheduled(1), /persisted canonical head/);
        for (const i of workers)
            await writeFile(join(out, `node${i}.toml`), scheduled(fromBlock));
        await start(0);
        await start(1, boot);
        await start(2, boot);
        if (lateJoin) {
            await start(3, boot);
            await until(async () => {
                const record = await rpc(3, 'shell_getRegisteredProver', [keys[3].address]);
                return Number(BigInt(await rpc(3, 'net_peerCount'))) > 0 && !!record &&
                    BigInt(await rpc(3, 'eth_getBalance', [recipient, 'latest'])) === 512n;
            }, 90);
            assert.equal(BigInt(await rpc(3, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])), 512n);
            assert.equal(count(await metricText(3)), 0, 'fresh epoch-only worker must not prove historical ranges');
            result.lateJoin = { beforeNewWindow: await rpc(3, 'shell_getNodeInfo'), historicalBalance: '512', historicalNonce: '512', historicalGenerated: 0 };
            await save();
        }
        const settlementCount = async () => {
            const records = await Promise.all(workers.map(i => rpc(0, 'shell_getRegisteredProver', [keys[i].address])));
            return records.reduce((n, x) => n + x.proofs_submitted, 0);
        };
        const submitWindow = async (firstNonce) => {
            for (let offset = firstNonce; offset < firstNonce + 512; offset += 16) {
                const hashes = [];
                for (let nonce = offset; nonce < offset + 16; nonce++) {
                    const tx = await sender.buildSignedTransaction({ tx: buildTransaction({ chainId: 1337, nonce, to: recipient, value: 1n, gasLimit: 21000 }), includePublicKey: true });
                    hashes.push(await paced(() => provider.sendTransaction(tx)));
                }
                for (const hash of hashes) {
                    const receipt = await until(() => rpc(0, 'eth_getTransactionReceipt', [hash]));
                    assert.equal(receipt.status, '0x1');
                    result.receipts.push(receipt);
                }
            }
        };
        // The first post-restart range may start BEFORE the new epoch and cross
        // its activation. It must finish whole under the original membership.
        await submitWindow(512);
        await until(async () => await settlementCount() === 2, 90);
        const before = await Promise.all(workers.map(async (i) => count(await metricText(i))));
        assert.equal(before.reduce((n, x) => n + x, 0), 1, 'crossing range generated exactly once');
        await submitWindow(1024);
        await until(async () => await settlementCount() === 3, 90);
        await pause(1500);
        const after = await Promise.all(workers.map(async (i) => count(await metricText(i))));
        for (const i of workers)
            assert.equal(after[i - 1] - before[i - 1], i === target ? 1 : 0, 'only the future member generates the later range');
        const ranges = [];
        for (const i of workers) {
            const log = await readFile(join(out, `node${i}.log`), 'utf8');
            for (const match of log.matchAll(/range ending at block #(\d+) \((\d+) source hashes\)/g)) {
                ranges.push({ worker: i, end: Number(match[1]), start: Number(match[1]) - Number(match[2]) + 1 });
            }
        }
        ranges.sort((a, b) => a.start - b.start);
        assert.equal(ranges.length, 2);
        assert.equal(ranges[0].start, crossingStart);
        assert.equal(ranges[0].worker, crossingWorker, 'crossing range stays with its old-epoch owner');
        assert.notEqual(crossingWorker, target);
        assert.ok(ranges[0].start < fromBlock && ranges[0].end >= fromBlock, 'actual range crosses activation without splitting');
        assert.ok(ranges[1].start >= fromBlock);
        assert.equal(ranges[1].worker, target);
        assert.equal(ranges[0].end + 1, ranges[1].start, 'no skipped or overlapping sources');
        result.schedule = { fromBlock, target, crossingWorker, crossingStart, firstSourceHash: firstSource.hash, before, after, ranges };
        assert.equal(BigInt(await rpc(0, 'eth_getBalance', [recipient, 'latest'])), 1536n);
        assert.deepEqual(await rpc(0, 'shell_getValidators'), validators);
        await stopAll();
        await failStart('static-downgrade', base, /persisted assignment/);
        await failStart('rewritten-epoch', scheduled(fromBlock).replace(JSON.stringify([keys[target].address]), JSON.stringify([keys[crossingWorker].address])), /persisted assignment/);
        await writeFile(cfg, scheduled(fromBlock));
        await start(0);
        await start(1, boot);
        await start(2, boot);
        if (lateJoin) await start(3, boot);
        const finalReceipt = result.receipts.at(-1);
        for (let i = 0; i < nodeCount; i++) {
            await until(async () => BigInt(await rpc(i, 'eth_getBalance', [recipient, 'latest'])) === 1536n);
            assert.equal(BigInt(await rpc(i, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])), 1536n);
            assert.equal((await rpc(i, 'eth_getTransactionReceipt', [finalReceipt.transactionHash])).status, '0x1');
        }
        await pause(1500);
        for (const i of workers)
            assert.equal(count(await metricText(i)), 0, 'scheduled reopen does not recompute');
        assert.equal(await settlementCount(), 3, 'settled prover records persist after reopen');
        if (lateJoin) {
            assert.equal((await rpc(3, 'shell_getRegisteredProver', [keys[3].address])).proofs_submitted, 1);
            result.lateJoin.reopenPassed = true;
        }
        result.schedule.reopenPassed = true;
        result.accepted = result.receipts.length;
        result.recipientBalance = '1536';
        result.adaptation = 'Explicit coordinated future memberships, local registry activation0, 1536 genuine transfers. Automatic recruitment and offline takeover remain unqualified.';
    }
    result.reopenPassed = true;
    result.status = reconfigure ? 'PASS: scheduled membership, crossing and later ranges, 1536 genuine transfers, persistent schedule and native reopens' : 'PASS: one actual proof, unchanged validators, genuine receipts/state and all three native RocksDB reopens';
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
