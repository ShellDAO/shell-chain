#!/usr/bin/env python3
"""Real CLI, RocksDB and HTTP acceptance for operator monitoring (Python 3)."""
from pathlib import Path
import datetime
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
root = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', str(root / 'target/debug/shell-node'))).resolve()
if not binary.is_file():
    raise SystemExit('Build shell-node first or set SHELL_NODE_BIN')
out = Path(tempfile.mkdtemp(prefix='shell-monitoring-'))
os.chmod(out, 0o700)
audit = out / 'results'
audit.mkdir()
key = out / 'validator.json'
pw = out / 'password'
pw.write_text(secrets.token_hex(24))
os.chmod(pw, 0o600)
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    metrics_port = s.getsockname()[1]
url = f'http://127.0.0.1:{port}'
node = None
node_log = None
result = {
    'start': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'out': str(out),
    'binary_version': subprocess.check_output([str(binary), '--version'], text=True).strip(),
    'commands': [],
    'adaptations': ['Fresh isolated RocksDB directories, keys and RPC port', 'Current debug binary instead of repeating the release build', 'Automatic 10-second dev blocks create a measurable pending window; no public-network claim'],
}

def save():
    (audit / 'runtime.json').write_text(json.dumps(result, indent=2) + '\n')

def run(label, args, expect=0):
    command = [str(binary), *map(str, args)]
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    r = subprocess.run(command, cwd=out, text=True, capture_output=True, timeout=120)
    (audit / f'{label}.log').write_text(r.stdout + r.stderr)
    result['commands'].append({'label': label, 'command': command, 'cwd': str(out), 'start': start, 'end': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'exit_code': r.returncode})
    save()
    if expect is not None:
        assert r.returncode == expect, (label, r.returncode, r.stderr)
    return r

def rpc(method, params=None):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as f:
        d = json.load(f)
    if 'error' in d:
        raise RuntimeError(d['error'])
    return d['result']

def stop():
    global node, node_log
    if node and node.poll() is None:
        node.terminate()
        try:
            node.wait(timeout=20)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait()
    node = None
    if node_log:
        node_log.close()
        node_log = None

def start(data, label):
    global node, node_log
    cmd = [str(binary), 'run', '--datadir', str(data), '--keystore', str(key), '--password-file', str(pw), '--rpc-addr', f'127.0.0.1:{port}', '--metrics-addr', f'127.0.0.1:{metrics_port}', '--block-time', '10000', '--max-idle-interval', '1209600000', '--network', 'dev', '--db', 'rocksdb', '--rpc-api', 'eth,net,web3,shell,evm']
    node_log = (out / f'{label}-node.log').open('w')
    node = subprocess.Popen(cmd, stdout=node_log, stderr=subprocess.STDOUT)
    result['current_pid'] = node.pid
    save()
    for _ in range(160):
        if node.poll() is not None:
            raise RuntimeError(f'{label} exited: ' + (out / f'{label}-node.log').read_text()[-2500:])
        try:
            rpc('eth_blockNumber')
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError('startup timeout')

def endpoint(path):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{metrics_port}' + path, timeout=5) as f:
            return {'status': f.status, 'body': f.read().decode()}
    except urllib.error.HTTPError as e:
        return {'status': e.code, 'body': e.read().decode()}

def sample(label):
    health = endpoint('/health')
    ready = endpoint('/ready')
    exposition = endpoint('/metrics')
    (audit / f'{label}.prom').write_text(exposition['body'])
    values = {line.split()[0]: float(line.split()[1]) for line in exposition['body'].splitlines() if line and (not line.startswith('#')) and (len(line.split()) == 2) and ('{' not in line)}
    d = {
        'health': health,
        'ready': ready,
        'rpc_height': rpc('eth_blockNumber'),
        'metrics': values,
        'rpc_pending_block': rpc('eth_getBlockByNumber', ['pending', False]),
    }
    result[label] = d
    save()
    return d
try:
    run('key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', key])
    inspected = run('inspect', ['key', 'inspect', key])
    address = next((x.split('Address:', 1)[1].strip() for x in inspected.stdout.splitlines() if 'Address:' in x))
    recipient = '0x' + '42' * 32
    genesis = {
        'chain_id': 1337,
        'chain_name': 'monitoring-acceptance',
        'network_type': 'Dev',
        'timestamp': int(time.time()),
        'gas_limit': 30000000,
        'extra_data': 'monitoring-acceptance',
        'consensus': {'engine': 'poa', 'authorities': [address], 'block_time_secs': 2, 'epoch_length': 0},
        'alloc': {address: {'balance': '0x3635c9adc5dea00000'}},
        'boot_nodes': [],
    }
    genesis_file = out / 'genesis.json'
    genesis_file.write_text(json.dumps(genesis, indent=2))
    data = out / 'node'
    run('init', ['--datadir', data, 'init', '--genesis', genesis_file, '--chain-id', '1337', '--network', 'dev'])
    start(data, 'initial')
    initial = sample('initial')
    tx = run('submit', ['--password-file', pw, 'tx', 'send', '--to', recipient, '--value', str(10 ** 18), '--keystore', key, '--rpc-url', url])
    txhash = re.search('0x[0-9a-f]{64}', tx.stdout).group(0)
    pending = sample('pending')
    rejected = run('reject-insufficient-balance', ['--password-file', pw, 'tx', 'send', '--to', recipient, '--value', str(10 ** 30), '--gas-limit', '21000', '--nonce', '1', '--keystore', key, '--rpc-url', url], expect=1)
    assert 'balance' in (rejected.stdout + rejected.stderr).lower()
    after_rejection = sample('after-rejection')
    receipt = None
    for _ in range(100):
        receipt = rpc('eth_getTransactionReceipt', [txhash])
        if receipt:
            break
        time.sleep(0.25)
    assert receipt and receipt['status'] == '0x1'
    result['receipt'] = receipt
    # Receipt publication precedes the event-loop metrics update.
    for _ in range(100):
        if 'shell_block_height 1\n' in endpoint('/metrics')['body']:
            break
        time.sleep(0.05)
    mined = sample('mined')
    stop()
    start(data, 'restarted')
    for _ in range(40):
        if endpoint('/ready')['status'] == 200:
            break
        time.sleep(0.25)
    restarted = sample('restarted')
    result['assertions'] = {
        'genesis_liveness': initial['health']['status'] == 200 and json.loads(initial['health']['body'])['block_height'] == 0,
        'genesis_not_ready': initial['ready']['status'] == 503,
        'pending_pool_observed': pending['metrics']['shell_tx_pool_size'] == len(pending['rpc_pending_block']['transactions']) == 1,
        'rejection_preserves_pool_metrics': after_rejection['metrics']['shell_txs_received_total'] == 1 and after_rejection['metrics']['shell_tx_pool_size'] == 1,
        'production_observed': mined['metrics']['shell_block_production_duration_seconds_count'] == 1,
        'accepted_rpc_transaction_counted': pending['metrics']['shell_txs_received_total'] == 1,
        'mined_height_matches_rpc': mined['metrics']['shell_block_height'] == int(mined['rpc_height'], 16) == 1,
        'ready_after_block': mined['ready']['status'] == 200,
        'pool_drained': mined['metrics']['shell_tx_pool_size'] == 0,
        'restart_height': json.loads(restarted['health']['body'])['block_height'] == 1,
        'restart_ready': restarted['ready']['status'] == 200,
        'restart_counter_reset': restarted['metrics']['shell_txs_received_total'] == 0,
    }
    result['passed'] = all(result['assertions'].values())
    print(json.dumps(result['assertions']), flush=True)
    assert result['passed'], 'monitoring assertions failed'
except BaseException as e:
    result['error'] = str(e)
    raise
finally:
    stop()
    if node_log:
        node_log.close()
    result['nodesStopped'] = True
    result['end'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(f'Results and isolated node data: {out}', flush=True)
