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
const delayedPredecessor = process.env.SHELL_COHORT_DELAY_PREDECESSOR === '1';
const parallelWorkers = process.env.SHELL_COHORT_PARALLEL === '1';
const connectedWorkers = process.env.SHELL_COHORT_CONNECTED === '1';
const registryWorkers = process.env.SHELL_COHORT_REGISTRY === '1';
assert.ok([delayedPredecessor, parallelWorkers, connectedWorkers, registryWorkers].filter(Boolean).length <= 1 && (!(delayedPredecessor || parallelWorkers || connectedWorkers || registryWorkers) || !reconfigure), 'Run connected, parallel, delayed predecessor and registry or scheduled membership scenarios separately');
const nodeCount = lateJoin || registryWorkers ? 4 : 3;
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
async function start(i, boot, role = i === 0 ? 'validator' : 'prover') {
    result.nodesStopped = false;
    const args = [
        '--password-file', password, 'run', '--keystore', join(out, `key${i}.json`), '--config', join(out, `node${i}.toml`), '--datadir', join(out, `db${i}`), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb', '--rpc-addr', `127.0.0.1:${ports[i]}`, '--metrics-addr', `127.0.0.1:${metrics[i]}`, '--p2p', '--p2p-addr', `127.0.0.1:${p2p[i]}`, '--node-role', role, '--enable-stark-aggregation', '--consensus-engine', 'wpoa', '--block-time', '1000', '--max-idle-interval', '0', '--log-level', 'info'
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
async function checkDelayedPredecessor(boot, validators) {
    result.adaptation = connectedWorkers ? 'Explicit scheduled ownership, connected native workers and an authority kept running during proof computation; 1024 genuine transfers. No automatic recruitment, takeover or throughput claim.' : parallelWorkers ? 'Explicit scheduled ownership and overlapping native CPU proof calls, 1024 genuine transfers. No automatic recruitment, takeover or throughput claim.' : 'Explicit scheduled ownership and delayed predecessor startup, 1024 genuine transfers. No automatic recruitment or takeover.';
    const provider = createShellProvider({ rpcHttpUrl: `http://127.0.0.1:${ports[0]}` });
    const recipient = '0x' + 'ab'.repeat(32);
    // Accumulate two genuine windows before either CPU proof worker starts.
    for (let offset = 0; offset < 1024; offset += 16) {
        const hashes = [];
        for (let nonce = offset; nonce < offset + 16; nonce++) {
            const tx = await sender.buildSignedTransaction({
                tx: buildTransaction({ chainId: 1337, nonce, to: recipient, value: 1n, gasLimit: 21000 }),
                includePublicKey: true
            });
            hashes.push(await paced(() => provider.sendTransaction(tx)));
        }
        for (const hash of hashes) {
            const receipt = await until(() => rpc(0, 'eth_getTransactionReceipt', [hash]));
            assert.equal(receipt.status, '0x1');
            result.receipts.push(receipt);
        }
        result.accepted = result.receipts.length;
        await save();
    }
    // Determine complete-block windows before any worker runs. Each submitted
    // transfer and each registry governance request contributes one signature.
    // System reward transactions do not contribute a user signature.
    const signedHashes = new Set([
        ...result.receipts.map(receipt => receipt.transactionHash),
        result.registration1.hash, result.registration2.hash
    ]);
    assert.equal(signedHashes.size, 1026);
    const expectedRanges = [];
    let rangeStart = 0, entries = 0, nonEmptySources = 0, observed = 0;
    const sourceHead = Number(BigInt(result.receipts.at(-1).blockNumber));
    for (let height = 0; height <= sourceHead; height++) {
        const block = await rpc(0, 'eth_getBlockByNumber', ['0x' + height.toString(16), true]);
        const count = block.transactions.filter(tx => signedHashes.has(tx.hash)).length;
        observed += count;
        entries += count;
        if (count) nonEmptySources++;
        if (entries >= 512) {
            expectedRanges.push({ start: rangeStart, end: height, entries, nonEmptySources });
            rangeStart = height + 1;
            entries = 0;
            nonEmptySources = 0;
        }
    }
    assert.equal(observed, 1026, 'all submitted signed inputs are canonical');
    assert.equal(expectedRanges.length, 2);
    const fromBlock = expectedRanges[1].start;
    result.expectedCompletionRanges = expectedRanges;
    result.completionTailEntries = entries;
    assert.ok(entries < 512, 'only a sub-threshold tail may remain unproved');
    const config = '[network]\nenable_mdns=false\n[prover]\nproving_priority="sequential"\nworker_cohort=' +
        JSON.stringify([keys[1].address]) + '\n[[prover.worker_cohort_schedule]]\nfrom_block=' +
        fromBlock + '\nworkers=' + JSON.stringify([keys[2].address]) + '\n';
    for (const i of [1, 2]) await writeFile(join(out, `node${i}.toml`), config);
    const record = i => rpc(0, 'shell_getRegisteredProver', [keys[i].address]);
    let laterGenerated, originalProofHash, generated, ranges;
    if (connectedWorkers) {
        // Keep the authority online through both workers' normal sync and proving.
        await Promise.all([1, 2].map(i => start(i, boot)));
        await until(async () => (await Promise.all([1, 2].map(async i => count(await metricText(i))))).every(n => n === 1), 90);
        await until(async () => (await record(1)).proofs_submitted === 1 && (await record(2)).proofs_submitted === 1, 90);
        generated = await Promise.all([1, 2].map(async i => count(await metricText(i))));
        assert.deepEqual(generated, [1, 1], 'connected workers generate only their assigned ranges');
        const intervals = [], proofSha256 = [], peerCounts = [];
        ranges = [];
        for (const i of [1, 2]) {
            const log = await readFile(join(out, `node${i}.log`), 'utf8');
            const starts = log.split('\n').filter(line => line.includes('STARK CPU proof started'));
            const ends = log.split('\n').filter(line => line.includes('STARK CPU proof finished'));
            assert.equal(starts.length, 1);
            assert.equal(ends.length, 1);
            assert.match(ends[0], /success=true/);
            const begin = Date.parse(starts[0].split(/\s+/)[0]);
            const end = Date.parse(ends[0].split(/\s+/)[0]);
            assert.ok(Number.isFinite(begin) && end > begin);
            intervals.push({ worker: i, begin, end, startLog: starts[0], endLog: ends[0] });
            const stored = [...log.matchAll(/range ending at block #(\d+) \((\d+) source hashes\)/g)];
            assert.equal(stored.length, 1);
            const range = { worker: i, end: Number(stored[0][1]), start: Number(stored[0][1]) - Number(stored[0][2]) + 1 };
            assert.equal(range.start, expectedRanges[i - 1].start);
            assert.equal(range.end, expectedRanges[i - 1].end);
            ranges.push(range);
            const peers = Number(BigInt(await rpc(i, 'net_peerCount')));
            assert.ok(peers > 0, 'proof worker remains connected to the running native network');
            peerCounts.push(peers);
            assert.ok(log.split('\n').some(line => line.includes('peer connected') && Date.parse(line.split(/\s+/)[0]) <= begin), 'normal peer connection precedes actual CPU proving');
            const block = await rpc(i, 'eth_getBlockByNumber', ['0x' + range.end.toString(16), false]);
            const saved = await rpc(i, 'shell_getProofAmendment', [block.hash]);
            assert.equal(saved.proof_entries, expectedRanges[i - 1].entries);
            proofSha256.push(createHash('sha256').update(Buffer.from(saved.proof.slice(2), 'hex')).digest('hex'));
        }
        const overlapMs = Math.min(...intervals.map(x => x.end)) - Math.max(...intervals.map(x => x.begin));
        result.connectedCpu = { intervals, overlapMs, generated, ranges, proofSha256, peerCounts, topology: 'Both workers connected to a continuously running native authority; CPU overlap measured without treating useful work as a throughput benchmark' };
        assert.ok(overlapMs > 0, 'independent connected native CPU proof calls must overlap');
        assert.equal(count(await metricText(0)), 0, 'authority does no CPU proving');
        laterGenerated = generated[1];
        result.completionOrder = { fromBlock, laterRange: ranges[1], connectedWorkers: true };
        await save();
    } else if (parallelWorkers) {
        // Synchronize both databases using the normal validator role, which does
        // no CPU proof work. Restart both normal prover processes together so
        // their independent assigned ranges are available at startup.
        await Promise.all([1, 2].map(i => start(i, boot, 'validator')));
        for (const i of [1, 2]) {
            await until(async () => BigInt(await rpc(i, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])) === 1024n);
            assert.equal(count(await metricText(i)), 0);
        }
        await stopAll();
        // Pre-synchronized dev nodes can compute without peers. Keep the
        // authority stopped during computation so changing empty tips and
        // independent sync handshakes cannot stagger these short proof calls.
        // No proof call is paused, delayed or replaced.
        await Promise.all([1, 2].map(i => start(i)));
        await until(async () => (await Promise.all([1, 2].map(async i => count(await metricText(i))))).every(n => n === 1), 90);
        await until(async () => (await Promise.all([1, 2].map(async i => /ProverService: proof amendment stored/.test(await readFile(join(out, `node${i}.log`), 'utf8'))))).every(Boolean));
        generated = await Promise.all([1, 2].map(async i => count(await metricText(i))));
        assert.deepEqual(generated, [1, 1], 'each worker generates exactly its own proof');
        const intervals = [];
        ranges = [];
        for (const i of [1, 2]) {
            const log = await readFile(join(out, `node${i}.log`), 'utf8');
            const starts = log.split('\n').filter(line => line.includes('STARK CPU proof started'));
            const ends = log.split('\n').filter(line => line.includes('STARK CPU proof finished'));
            assert.equal(starts.length, 1);
            assert.equal(ends.length, 1);
            assert.match(ends[0], /success=true/);
            const begin = Date.parse(starts[0].split(/\s+/)[0]);
            const end = Date.parse(ends[0].split(/\s+/)[0]);
            assert.ok(Number.isFinite(begin) && end > begin, 'actual CPU call has timestamped endpoints');
            intervals.push({ worker: i, begin, end, startLog: starts[0], endLog: ends[0] });
            const stored = [...log.matchAll(/range ending at block #(\d+) \((\d+) source hashes\)/g)];
            assert.equal(stored.length, 1);
            const range = { worker: i, end: Number(stored[0][1]), start: Number(stored[0][1]) - Number(stored[0][2]) + 1 };
            assert.equal(range.start, expectedRanges[i - 1].start);
            assert.equal(range.end, expectedRanges[i - 1].end);
            ranges.push(range);
        }
        const overlapMs = Math.min(...intervals.map(x => x.end)) - Math.max(...intervals.map(x => x.begin));
        const proofSha256 = [];
        for (const i of [1, 2]) {
            assert.equal(BigInt(await rpc(i, 'net_peerCount')), 0n, 'computation uses the pre-synchronized isolated dev topology');
            const block = await rpc(i, 'eth_getBlockByNumber', ['0x' + expectedRanges[i - 1].end.toString(16), false]);
            const saved = await rpc(i, 'shell_getProofAmendment', [block.hash]);
            assert.equal(saved.proof_entries, expectedRanges[i - 1].entries);
            proofSha256.push(createHash('sha256').update(Buffer.from(saved.proof.slice(2), 'hex')).digest('hex'));
        }
        result.parallelCpu = { intervals, overlapMs, generated, ranges, proofSha256, topology: 'Pre-synchronized isolated dev proof computation, then native network rejoin for settlement' };
        await save();
        assert.ok(overlapMs > 0, 'independent native CPU proof calls must overlap; successful settlement alone is insufficient');
        laterGenerated = generated[1];
        await stopAll();
        await start(0);
        await Promise.all([1, 2].map(i => start(i, boot)));
        await until(async () => (await record(1)).proofs_submitted === 1 && (await record(2)).proofs_submitted === 1, 90);
        assert.equal(count(await metricText(0)), 0, 'validator never generates a proof');
        result.parallelCpu.generatedAfterRejoin = await Promise.all([1, 2].map(async i => count(await metricText(i))));
        assert.deepEqual(result.parallelCpu.generatedAfterRejoin, [0, 0], 'network rejoin settles the persisted proofs without regeneration');
        result.completionOrder = { fromBlock, laterRange: ranges[1], parallelCpu: true };
    } else {
        await start(2, boot);
        await until(async () => count(await metricText(2)) === 1, 90);
        laterGenerated = count(await metricText(2));
        await until(async () => /G5: proof amendment artifacts stored/.test(await readFile(join(out, 'node0.log'), 'utf8')));
        assert.equal((await record(1)).proofs_submitted, 0);
        assert.equal((await record(2)).proofs_submitted, 0);
        const stored = await readFile(join(out, 'node2.log'), 'utf8');
        const range = stored.match(/range ending at block #(\d+) \((\d+) source hashes\)/);
        assert.ok(range, 'later proof persisted before predecessor');
        const laterRange = { end: Number(range[1]), start: Number(range[1]) - Number(range[2]) + 1 };
        assert.equal(laterRange.start, fromBlock);
        assert.equal(laterRange.end, expectedRanges[1].end);
        const laterBlock = await rpc(0, 'eth_getBlockByNumber', ['0x' + laterRange.end.toString(16), false]);
        const originalProof = await rpc(2, 'shell_getProofAmendment', [laterBlock.hash]);
        assert.equal(originalProof.proof_entries, expectedRanges[1].entries);
        originalProofHash = createHash('sha256').update(Buffer.from(originalProof.proof.slice(2), 'hex')).digest('hex');
        const peerProof = await rpc(0, 'shell_getProofAmendment', [laterBlock.hash]);
        assert.equal(peerProof.proof, originalProof.proof, 'independent validator retained the actual later proof');
        result.completionOrder = { fromBlock, laterRange, laterGeneratedBeforePredecessor: laterGenerated, settlementsBeforePredecessor: 0 };
        result.completionOrder.originalLaterProofSha256 = originalProofHash;
        await stopAll();
        await start(0);
        await start(2, boot);
        await until(async () => BigInt(await rpc(2, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])) === 1024n);
        // Poll after multiple admission ticks so a regenerated proof cannot hide
        // behind an immediate zero-valued metric after process startup.
        await pause(2500);
        assert.equal(count(await metricText(2)), 0, 'persisted later proof survives cold reopen without recomputation');
        for (const i of [0, 2]) {
            const saved = await rpc(i, 'shell_getProofAmendment', [laterBlock.hash]);
            assert.ok(saved?.proof, 'waiting proof survives both physical database reopens');
            assert.equal(createHash('sha256').update(Buffer.from(saved.proof.slice(2), 'hex')).digest('hex'), originalProofHash);
        }
        assert.equal((await record(2)).proofs_submitted, 0, 'later proof cannot settle across the gap');
        await start(1, boot);
        await until(async () => (await record(1)).proofs_submitted === 1 && (await record(2)).proofs_submitted === 1, 90);
        assert.equal(count(await metricText(0)), 0, 'validator recovers stored proofs without CPU proving');
        generated = await Promise.all([1, 2].map(async i => count(await metricText(i))));
        assert.deepEqual(generated, [1, 0], 'only the missing predecessor is computed after reopen');
        ranges = [];
        for (const i of [1, 2]) {
            const log = await readFile(join(out, `node${i}.log`), 'utf8');
            for (const m of log.matchAll(/range ending at block #(\d+) \((\d+) source hashes\)/g)) {
                ranges.push({ worker: i, end: Number(m[1]), start: Number(m[1]) - Number(m[2]) + 1 });
            }
        }
        assert.equal(ranges.length, 1);
        assert.equal(ranges[0].start, 0);
        assert.equal(ranges[0].end + 1, laterRange.start);
    }
    const laterRange = { start: fromBlock, end: expectedRanges[1].end };
    const rewardPayloads = [];
    const lastHeight = Number(BigInt(await rpc(0, 'eth_blockNumber')));
    for (let height = laterRange.end + 1; height <= lastHeight; height++) {
        const block = await rpc(0, 'eth_getBlockByNumber', ['0x' + height.toString(16), true]);
        for (const tx of block.transactions) {
            if (tx.type === '0x81') rewardPayloads.push(tx);
        }
    }
    assert.equal(rewardPayloads.length, 2, 'both original proofs settle exactly once');
    const canonical = await rpc(0, 'eth_getBlockByNumber', ['0x' + lastHeight.toString(16), false]);
    const rewards = [];
    for (let batch = 0; batch < 2; batch++) {
        const tx = rewardPayloads[batch];
        const amendment = tx.decodedInput;
        assert.ok(amendment, 'settlement exposes its actual proof payload');
        assert.equal(amendment.prover.toLowerCase(), keys[batch + 1].address.toLowerCase());
        assert.equal(amendment.start_block, expectedRanges[batch].start);
        assert.equal(amendment.end_block, expectedRanges[batch].end);
        assert.equal(amendment.proof.n_sigs, expectedRanges[batch].entries);
        if (parallelWorkers || connectedWorkers) {
            const proofHex = '0x' + Buffer.from(amendment.proof.proof_bytes).toString('hex');
            assert.equal(createHash('sha256').update(Buffer.from(proofHex.slice(2), 'hex')).digest('hex'), (parallelWorkers ? result.parallelCpu : result.connectedCpu).proofSha256[batch], 'settlement uses the original native CPU proof bytes');
        }
        if (batch === 1 && !parallelWorkers && !connectedWorkers) {
            const proofHex = '0x' + Buffer.from(amendment.proof.proof_bytes).toString('hex');
            assert.equal(createHash('sha256').update(Buffer.from(proofHex.slice(2), 'hex')).digest('hex'), originalProofHash, 'settlement uses the original later proof bytes');
        }
        const expected = 50_000_000_000_000_000_000n * BigInt(expectedRanges[batch].nonEmptySources);
        assert.equal(BigInt(tx.value), expected);
        assert.equal(BigInt(await rpc(0, 'eth_getBalance', [keys[batch + 1].address, 'latest'])), expected);
        assert.equal((await rpc(0, 'eth_getTransactionReceipt', [tx.hash])).status, '0x1');
        rewards.push(expected.toString());
    }
    result.completionOrder.predecessorRange = ranges[0];
    result.completionOrder.generatedAfterReopen = generated;
    result.completionOrder.records = await Promise.all([1, 2].map(record));
    result.completionOrder.rewardTransactions = rewardPayloads;
    result.completionOrder.rewards = rewards;
    result.recipientBalance = '1024';
    const last = result.receipts.at(-1);
    for (const i of [0, 1, 2]) {
        await until(async () => (await rpc(i, 'eth_getTransactionReceipt', [last.transactionHash]))?.status === '0x1' &&
            BigInt(await rpc(i, 'eth_getBalance', [recipient, 'latest'])) === 1024n);
        assert.equal(BigInt(await rpc(i, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])), 1024n);
        assert.deepEqual(await rpc(i, 'shell_getValidators'), validators);
        await until(async () => {
            const records = await Promise.all([1, 2].map(worker => rpc(i, 'shell_getRegisteredProver', [keys[worker].address])));
            const finalized = await rpc(i, 'eth_getBlockByNumber', ['finalized', false]);
            return records.every(item => item.proofs_submitted === 1) && BigInt(finalized.number) >= BigInt(lastHeight);
        });
        assert.equal((await rpc(i, 'eth_getBlockByNumber', [canonical.number, false])).hash, canonical.hash);
    }
    await stopAll();
    await start(0);
    await start(1, boot);
    await start(2, boot);
    for (const i of [0, 1, 2]) {
        assert.equal(BigInt(await rpc(i, 'eth_getBalance', [recipient, 'latest'])), 1024n);
        assert.equal(BigInt(await rpc(i, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])), 1024n);
        for (const worker of [1, 2]) {
            assert.equal((await rpc(i, 'shell_getRegisteredProver', [keys[worker].address])).proofs_submitted, 1);
            assert.equal(BigInt(await rpc(i, 'eth_getBalance', [keys[worker].address, 'latest'])), BigInt(rewards[worker - 1]));
        }
    }
    await pause(1500);
    for (const i of [1, 2]) assert.equal(count(await metricText(i)), 0, 'settled ranges are not regenerated after all nodes reopen');
    result.workers = [1, 2].map(i => ({ i, generated: i === 1 ? generated[0] : laterGenerated, generationLogs: [], record: result.completionOrder.records[i - 1] }));
    result.status = connectedWorkers ? 'PASS: connected native workers, disjoint proof ranges, original proof settlement, exact rewards, 1024 genuine transfers and all native reopens' : parallelWorkers ? 'PASS: overlapping native CPU proof calls, disjoint canonical ranges, exact rewards, 1024 genuine transfers and all native reopens' : 'PASS: later proof completed first, persisted across cold reopen, both original ranges settled once, 1024 genuine transfers and all native reopens';
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
        await writeFile(join(out, `node${i}.toml`), '[network]\nenable_mdns=false\n[prover]\nproving_priority="sequential"\n' + (registryWorkers ? 'worker_cohort_from_registry=true\n' : 'worker_cohort=' + JSON.stringify(keys.slice(1, 3).map(k => k.address)) + '\n'));
    if (delayedPredecessor || parallelWorkers || connectedWorkers) {
        await checkDelayedPredecessor(boot, validators);
    } else {
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
        assert.match(wrong.stdout + wrong.stderr, registryWorkers ? /registry-derived worker cohort/ : /persisted assignment/);
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
        if (registryWorkers) {
            const firstEnd = Number(result.workers.flatMap(w => w.generationLogs).join('\n').match(/range ending at block #(\d+)/)[1]);
            const firstBlock = await rpc(0, 'eth_getBlockByNumber', ['0x' + firstEnd.toString(16), false]);
            const initialProof = await rpc(0, 'shell_getProofAmendment', [firstBlock.hash]);
            const initialDigest = createHash('sha256').update(Buffer.from(initialProof.proof.slice(2), 'hex')).digest('hex');
            const next = await rpc(0, 'eth_getBlockByNumber', ['0x' + (firstEnd + 1).toString(16), false]);
            const rank = Number(BigInt('0x' + next.hash.slice(2, 18)) % 3n);
            // Select an unused fresh identity for this deterministic owner slot;
            // existing worker configuration and membership history stay untouched.
            let chosen = false;
            await writeFile(join(out, 'unused-initial-key3.json'), await readFile(join(out, 'key3.json')));
            for (let attempt = 0; attempt < 64; attempt++) {
                const candidatePath = join(out, `candidate-key3-${attempt}.json`);
                cli('joining-key', ['--password-file', password, 'key', 'generate', '--algorithm', 'mldsa65', '--output', candidatePath]);
                const candidate = JSON.parse(await readFile(candidatePath, 'utf8'));
                const members = [...keys.slice(1, 3).map(k => k.address.toLowerCase()), candidate.address.toLowerCase()].sort();
                if (members.indexOf(candidate.address.toLowerCase()) === rank) {
                    keys[3] = candidate;
                    await writeFile(join(out, 'key3.json'), await readFile(candidatePath));
                    chosen = true;
                    break;
                }
            }
            assert.ok(chosen, 'fresh joining identity occupies the next deterministic slot');
            result.addresses = keys.map(k => k.address);
            const hash = await rpc(0, 'shell_proposeRegisterProver', [keys[3].public_key, 1]);
            const receipt = await until(() => rpc(0, 'eth_getTransactionReceipt', [hash]));
            assert.equal(receipt.status, '0x1');
            await until(async () => !!(await rpc(0, 'shell_getRegisteredProver', [keys[3].address])));
            await writeFile(join(out, 'node3.toml'), '[network]\nenable_mdns=false\n[prover]\nworker_cohort_from_registry=true\n');
            await start(3, boot);
            await until(async () => BigInt(await rpc(3, 'eth_getTransactionCount', [sender.getAddress(), 'latest'])) === 512n);
            assert.equal(count(await metricText(3)), 0, 'joining worker does not regenerate settled historical work');
            for (let offset = 512; offset < 1024; offset += 16) {
                const hashes = [];
                for (let nonce = offset; nonce < offset + 16; nonce++) {
                    const tx = await sender.buildSignedTransaction({tx:buildTransaction({chainId:1337,nonce,to:recipient,value:1n,gasLimit:21000}),includePublicKey:true});
                    hashes.push(await paced(() => provider.sendTransaction(tx)));
                }
                for (const tx of hashes) {
                    const item = await until(() => rpc(0, 'eth_getTransactionReceipt', [tx]));
                    assert.equal(item.status, '0x1'); result.receipts.push(item);
                }
                await save();
            }
            await until(async () => (await rpc(0, 'shell_getRegisteredProver', [keys[3].address])).proofs_submitted === 1,90);
            assert.equal(count(await metricText(3)), 1);
            for (const i of [1,2]) assert.equal(count(await metricText(i)), 0, 'old workers discover the new owner without a schedule change');
            const record = await rpc(0, 'shell_getRegisteredProver', [keys[3].address]);
            const end = record.last_proof_block;
            const block = await rpc(0, 'eth_getBlockByNumber', ['0x' + end.toString(16), false]);
            const proof = await rpc(3, 'shell_getProofAmendment', [block.hash]);
            const digest = createHash('sha256').update(Buffer.from(proof.proof.slice(2), 'hex')).digest('hex');
            const known = new Set([...result.receipts.map(item => item.transactionHash), result.registration1.hash,result.registration2.hash,hash]);
            let nonEmpty = 0;
            for (let height = firstEnd+1; height <= end; height++) {
                const source = await rpc(0,'eth_getBlockByNumber',['0x'+height.toString(16),true]);
                if(source.transactions.some(tx => known.has(tx.hash))) nonEmpty++;
            }
            const reward = 50_000_000_000_000_000_000n * BigInt(nonEmpty);
            assert.equal(BigInt(await rpc(0,'eth_getBalance',[keys[3].address,'latest'])),reward);
            for (const i of [0,1,2,3]) {
                await until(async () => BigInt(await rpc(i,'eth_getBalance',[recipient,'latest']))===1024n &&
                    (await rpc(i,'shell_getRegisteredProver',[keys[3].address])).proofs_submitted===1);
                assert.equal(createHash('sha256').update(Buffer.from((await rpc(i,'shell_getProofAmendment',[block.hash])).proof.slice(2),'hex')).digest('hex'),digest);
                assert.equal(createHash('sha256').update(Buffer.from((await rpc(i,'shell_getProofAmendment',[firstBlock.hash])).proof.slice(2),'hex')).digest('hex'),initialDigest);
                assert.deepEqual(await rpc(i,'shell_getValidators'),validators);
            }
            const anchor = await rpc(0,'eth_getBlockByNumber',['latest',false]);
            for (const i of [0,1,2,3]) {
                await until(async () => BigInt((await rpc(i,'eth_getBlockByNumber',['finalized',false])).number)>=BigInt(anchor.number));
                const same = await rpc(i,'eth_getBlockByNumber',[anchor.number,false]);
                assert.equal(same.hash,anchor.hash); assert.equal(same.stateRoot,anchor.stateRoot);
                assert.equal(BigInt(await rpc(i,'eth_getBalance',[keys[3].address,'latest'])),reward);
            }
            await stopAll(); await start(0);
            for(const i of [1,2,3]) await start(i,boot);
            await pause(1500);
            for(const i of [0,1,2,3]) {
                assert.equal(BigInt(await rpc(i,'eth_getTransactionCount',[sender.getAddress(),'latest'])),1024n);
                assert.equal((await rpc(i,'shell_getRegisteredProver',[keys[3].address])).proofs_submitted,1);
                assert.equal(BigInt(await rpc(i,'eth_getBalance',[keys[3].address,'latest'])),reward);
                for (const [sourceHash, expected] of [[block.hash,digest],[firstBlock.hash,initialDigest]]) {
                    const stored = await rpc(i,'shell_getProofAmendment',[sourceHash]);
                    assert.equal(createHash('sha256').update(Buffer.from(stored.proof.slice(2),'hex')).digest('hex'),expected);
                }
                assert.equal((await rpc(i,'eth_getBlockByNumber',[anchor.number,false])).hash,anchor.hash);
                if(i>0) assert.equal(count(await metricText(i)),0,'registry cohort reopens without recomputation');
            }
            result.registryMembership={initialEnd:firstEnd,joiningAddress:keys[3].address,registrationHash:hash,registrationBlock:receipt.blockNumber,newRange:{start:firstEnd+1,end},proofSha256:digest,initialProofSha256:initialDigest,reward:reward.toString(),allFourReopened:true,canonicalAnchor:{number:anchor.number,hash:anchor.hash,stateRoot:anchor.stateRoot}};
            result.accepted=1024;result.recipientBalance='1024';
            result.adaptation='Opt-in canonical registry-derived ownership, fresh compatible discovery indexes, 1024 genuine transfers and a later registered worker; no manual worker address lists or epochs. Offline takeover and snapshot/legacy index rebuild remain unqualified.';
        }
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
        result.status = registryWorkers ? 'PASS: automatic canonical membership, live later recruitment, 1024 genuine transfers, original proof history, exact reward and all four native reopens' : reconfigure ? 'PASS: scheduled membership, crossing and later ranges, 1536 genuine transfers, persistent schedule and native reopens' : 'PASS: one actual proof, unchanged validators, genuine receipts/state and all three native RocksDB reopens';
    }
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
