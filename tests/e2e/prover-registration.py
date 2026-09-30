#!/usr/bin/env python3
"""Verify independent prover registration, real proof settlement and restart over P2P.

Requires Python 3 and source builds:
  cargo build -p shell-cli --bin shell-node --features libp2p
  cargo build -p shell-node --example prover-acceptance
Then run python3 tests/e2e/prover-registration.py (or --registration-only).
Uses fresh encrypted keys, isolated ports and private temporary RocksDB data.
The genesis activates prover_registry_height=0 only for this local test network.
The full mode submits 512 genuine signed transfers and checks an independent
prover's authenticated STARK, ordered settlement, replicated counters and restart.
Keeps private node data and receipts for inspection; stops both owned processes.
"""
from pathlib import Path
import argparse, datetime, json, os, re, secrets, socket, subprocess, tempfile, time, urllib.request
repo = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--registration-only', action='store_true', help='verify governance, unchanged authority and restart without full proof generation')
options = parser.parse_args()
binary = Path(os.environ.get('SHELL_NODE_BIN', str(repo / 'target/debug/shell-node'))).resolve()
helper = Path(os.environ.get('PROVER_ACCEPTANCE_BIN', str(repo / 'target/debug/examples/prover-acceptance'))).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-prover-registration-'))
os.chmod(out, 0o700)
audit = out / 'results'
audit.mkdir()
if not options.registration_only:
    subprocess.run([str(helper), 'inputs', str(out / 'inputs.json')], check=True)
    inputs = json.loads((out / 'inputs.json').read_text())
    txs = inputs['transactions']
else:
    inputs = {}
    txs = []
r = {'start': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'runtime': str(out), 'commands': [], 'receipts': [], 'scope': 'Isolated Dev1337 with explicit prover_registry_height=0; no public network or release activation.'}
proc = None
follower = None

def save():
    (audit / 'prover-registration.json').write_text(json.dumps(r, indent=2) + '\n')

def cli(label, args):
    cmd = [str(binary), *map(str, args)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    (audit / f'proof-peer-{label}.log').write_text(p.stdout + p.stderr)
    r['commands'].append({'command': cmd, 'exit_code': p.returncode})
    save()
    assert p.returncode == 0, (label, p.stderr)
    return p.stdout
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]

def rpc(method, params=None, rpc_port=None):
    # Keep submissions and observations below the default RPC request limit.
    time.sleep(0.05)
    req = urllib.request.Request(f'http://127.0.0.1:{rpc_port or port}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode(), {'Content-Type': 'application/json'})
    v = json.load(urllib.request.urlopen(req, timeout=10))
    assert 'error' not in v, v
    return v['result']

def until(fn, seconds=90):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        assert proc.poll() is None, 'node exited'
        try:
            v = fn()
            if v:
                return v
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError('Acceptance predicate unmet')

def start(suffix):
    global proc
    log = (audit / f'proof-peer-node{suffix}.log').open('w')
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env={**os.environ, 'RUST_LOG': 'info'})
    log.close()
    r['commands'].append({'command': cmd, 'pid': proc.pid})
    save()
    until(lambda: rpc('eth_blockNumber'), 30)

def stop_follower():
    if follower and follower.poll() is None:
        follower.terminate()
        try:
            follower.wait(timeout=30)
        except subprocess.TimeoutExpired:
            follower.kill()
            follower.wait()

def stop():
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
try:
    pw = out / 'password'
    pw.write_text(secrets.token_hex(24))
    os.chmod(pw, 0o600)
    key = out / 'validator.json'
    cli('key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', key])
    k = json.loads(key.read_text())
    prover_key = out / 'prover.json'
    cli('prover-key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', prover_key])
    pk = json.loads(prover_key.read_text())
    gen = out / 'genesis.json'
    gen.write_text(json.dumps({'prover_registry_height': 0, 'chain_id': 1337, 'chain_name': 'prover-execution', 'network_type': 'Dev', 'timestamp': int(time.time()), 'gas_limit': 30000000, 'extra_data': 'prover-execution', 'consensus': {'engine': 'wpoa', 'authorities': [k['address']], 'authority_pubkeys': ['0x' + k['public_key'].removeprefix('0x')], 'weights': [1], 'block_time_secs': 1, 'max_future_secs': 60, 'epoch_length': 0}, 'alloc': {**({inputs['address']: {'balance': '0x3635c9adc5dea00000'}} if inputs else {}), k['address']: {'balance': '0x3635c9adc5dea00000'}}, 'boot_nodes': []}))
    data = out / 'node'
    cli('init', ['--datadir', data, 'init', '--genesis', gen, '--chain-id', '1337', '--network', 'dev'])
    fdata = out / 'follower'
    cli('init-follower', ['--datadir', fdata, 'init', '--genesis', gen, '--chain-id', '1337', '--network', 'dev'])
    cfg = out / 'prover.toml'
    cfg.write_text('[node]\nnode_role="validator"\n[consensus]\nenable_stark_aggregation=true\n[metrics]\nenabled=false\n')
    cmd = [str(binary), '--password-file', str(pw), 'run', '--config', str(cfg), '--datadir', str(data), '--keystore', str(key), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb', '--rpc-addr', f'127.0.0.1:{port}', '--block-time', '1000', '--max-idle-interval', '0', '--consensus-engine', 'wpoa']
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        p2p = sock.getsockname()[1]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        fport = sock.getsockname()[1]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        fp2p = sock.getsockname()[1]
    cmd += ['--p2p', '--p2p-addr', f'127.0.0.1:{p2p}', '--log-level', 'info']
    start('')
    r['validators_before'] = rpc('shell_getValidators')
    assert rpc('shell_getRegisteredProver', [pk['address']]) is None
    registration = rpc('shell_proposeRegisterProver', [pk['public_key'], 1])
    registration_receipt = until(lambda: rpc('eth_getTransactionReceipt', [registration]))
    r['registration_receipt'] = registration_receipt
    assert registration_receipt['status'] == '0x1', registration_receipt
    r['registered'] = rpc('shell_getRegisteredProver', [pk['address']])
    assert r['registered']['pubkey'].removeprefix('0x') == pk['public_key'].removeprefix('0x')
    assert r['registered']['proofs_submitted'] == 0
    assert rpc('shell_getValidators') == r['validators_before']
    until(lambda: int(rpc('eth_getBlockByNumber', ['finalized', False])['number'], 16) >= int(registration_receipt['blockNumber'], 16))
    stop()
    start('-registration-restart')
    assert rpc('shell_getRegisteredProver', [pk['address']]) == r['registered']
    assert rpc('shell_getValidators') == r['validators_before']
    r['registration_persisted'] = True
    if options.registration_only:
        r['passed'] = True
        raise SystemExit(0)
    logtext = (audit / 'proof-peer-node-registration-restart.log').read_text()
    bootnode = re.findall('/ip4/127\\.0\\.0\\.1/tcp/\\d+/p2p/[A-Za-z0-9]+', logtext)[-1]
    fcmd = [str(binary), '--password-file', str(pw), 'run', '--keystore', str(prover_key), '--datadir', str(fdata), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb', '--rpc-addr', f'127.0.0.1:{fport}', '--p2p', '--p2p-addr', f'127.0.0.1:{fp2p}', '--bootnode', bootnode, '--node-role', 'prover', '--enable-stark-aggregation', '--consensus-engine', 'wpoa', '--log-level', 'info', '--metrics-addr', '127.0.0.1:0']
    flog = (audit / 'proof-peer-follower.log').open('w')
    follower = subprocess.Popen(fcmd, stdout=flog, stderr=subprocess.STDOUT, env={**os.environ, 'RUST_LOG': 'info'})
    flog.close()
    r['commands'].append({'command': fcmd, 'pid': follower.pid})
    save()
    until(lambda: int(rpc('net_peerCount'), 16) > 0 and int(rpc('net_peerCount', rpc_port=fport), 16) > 0)
    hashes = []
    for offset in range(0, 512, 16):
        batch = [rpc('eth_sendRawTransaction', [tx]) for tx in txs[offset:offset + 16]]
        for h in batch:
            receipt = until(lambda: rpc('eth_getTransactionReceipt', [h]))
            assert receipt['status'] == '0x1', receipt
            r['receipts'].append(receipt)
        hashes.extend(batch)
        r['accepted_count'] = len(hashes)
        save()
        print('accepted', len(hashes), flush=True)
    r['recipient_balance'] = rpc('eth_getBalance', ['0x' + 'ab' * 32, 'latest'])
    assert int(r['recipient_balance'], 16) == 512
    source_hashes = list(dict.fromkeys((x['blockHash'] for x in r['receipts'])))
    r['source_hashes'] = source_hashes
    r['sources'] = [rpc('eth_getBlockByHash', [h, False]) for h in source_hashes]
    save()

    def amendment():
        for h in source_hashes:
            a = rpc('shell_getProofAmendment', [h])
            if a and a.get('proof'):
                return a
        return None
    a = until(amendment, 120)
    assert a['prover'] == pk['address']
    r['settled_record'] = until(lambda: record if (record := rpc('shell_getRegisteredProver', [pk['address']]))['proofs_submitted'] > 0 else None, 120)
    assert r['settled_record']['last_proof_block'] == a['block_number']
    assert rpc('shell_getValidators') == r['validators_before']
    def settlement_finalized():
        current = rpc('shell_getProofAmendment', [a['block_hash']])
        if not current or not current.get('settlement_tx_hash'):
            return False
        receipt = rpc('eth_getTransactionReceipt', [current['settlement_tx_hash']])
        finalized = rpc('eth_getBlockByNumber', ['finalized', False])
        return receipt and finalized and int(finalized['number'], 16) >= int(receipt['blockNumber'], 16)
    until(settlement_finalized)
    a = rpc('shell_getProofAmendment', [a['block_hash']])
    payload = rpc('eth_getTransactionByHash', [a['settlement_tx_hash']])['input']
    (audit / 'amendment.json').write_bytes(bytes.fromhex(payload.removeprefix('0x')))
    subprocess.run([str(helper), 'verify', str(audit / 'amendment.json')], check=True)
    r['amendment'] = a
    save()
    assert a['proof_entries'] >= 512 and len(a['proof']) > 1000, a
    until(lambda: rpc('shell_getRegisteredProver', [pk['address']], rpc_port=fport) == r['settled_record'])
    fa = until(lambda: rpc('shell_getProofAmendment', [a['block_hash']], rpc_port=fport), 120)
    r['follower_amendment'] = fa
    assert rpc('shell_getRegisteredProver', [pk['address']], rpc_port=fport) == r['settled_record']
    assert fa.get('proof') == a['proof'] and fa['prover'] == pk['address'], 'recipient proof/prover mismatch'
    common = rpc('eth_getBlockByHash', [a['block_hash'], False], rpc_port=fport)
    assert common and common['hash'] == a['block_hash']
    r['follower_same_source'] = True
    stop_follower()
    flog = (audit / 'proof-peer-follower-restart.log').open('w')
    follower = subprocess.Popen(fcmd, stdout=flog, stderr=subprocess.STDOUT, env={**os.environ, 'RUST_LOG': 'info'})
    flog.close()
    fa2 = until(lambda: rpc('shell_getProofAmendment', [a['block_hash']], rpc_port=fport))
    r['follower_persisted'] = fa2 == fa
    assert r['follower_persisted']
    stop_follower()
    stop()
    start('-restart')
    after = rpc('shell_getProofAmendment', [a['block_hash']])
    assert rpc('shell_getRegisteredProver', [pk['address']]) == r['settled_record']
    r['persisted'] = after == a
    r['after_restart'] = after
    assert r['persisted']
    r['passed'] = True
except SystemExit:
    raise
except BaseException as e:
    r['error'] = repr(e)
    raise
finally:
    stop_follower()
    r['follower_stopped'] = follower is None or follower.poll() is not None
    stop()
    r['node_stopped'] = proc is None or proc.poll() is not None
    r['end'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({k: r[k] for k in ['runtime', 'accepted_count', 'passed', 'error', 'node_stopped'] if k in r}), flush=True)
