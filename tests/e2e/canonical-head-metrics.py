#!/usr/bin/env python3
"""Verify canonical tip metrics and probes through dev mining, rewind and reopen.

Build shell-node with libp2p, or set SHELL_NODE_BIN. Python 3 standard library
only. Creates fresh MLDSA65 keys, private Dev1337/RocksDB state and loopback
listeners. Keeps test data and exact receipts. Existing sync/production readiness
gates apply; no public network, transfers, database reset or activation changes.
"""
from pathlib import Path
import datetime, json, os, re, secrets, socket, subprocess, tempfile, time, urllib.error, urllib.request
repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', repo / 'target/debug/shell-node')).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-canonical-head-metrics-'))
out.chmod(0o700)
j = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'directory': str(out),
     'commands': [], 'processes': [], 'rpc': [], 'stages': {}}
process = None

def save():
    (out / 'results.json').write_text(json.dumps(j, indent=2) + '\n')

def cli(label, args):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=45)
    (out / (label + '.log')).write_text(result.stdout + result.stderr)
    j['commands'].append({'label': label, 'args': list(map(str, args)), 'exit_code': result.returncode})
    save()
    assert result.returncode == 0, (label, result.stderr)
    return result.stdout

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

rpc_port, metrics_port = port(), port()

def rpc(method, params=None, rejected=False):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}
    req = urllib.request.Request(f'http://127.0.0.1:{rpc_port}', json.dumps(body).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as response:
        value = json.load(response)
    j['rpc'].append({'request': body, 'response': value})
    save()
    assert ('error' in value) == rejected, value
    return value.get('result') if not rejected else value['error']

def get(path):
    try:
        response = urllib.request.urlopen(f'http://127.0.0.1:{metrics_port}/{path}', timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return {'status': response.status, 'body': response.read().decode()}

def start():
    global process
    args = ['--password-file', str(out / 'password'), 'run', '--datadir', str(out / 'data'),
            '--keystore', str(out / 'key.json'), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb',
            '--rpc-api', 'eth,shell,evm', '--rpc-addr', f'127.0.0.1:{rpc_port}',
            '--metrics-addr', f'127.0.0.1:{metrics_port}', '--p2p', '--p2p-addr', '127.0.0.1:0',
            '--node-role', 'validator', '--consensus-engine', 'wpoa', '--block-time', '1000',
            '--max-idle-interval', '1209600000']
    log = out / f'node-{len(j["processes"])}.log'
    with log.open('w') as stream:
        process = subprocess.Popen([str(binary), *args], stdout=stream, stderr=subprocess.STDOUT)
    j['processes'].append({'pid': process.pid, 'args': args, 'log': str(log), 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    save()
    for _ in range(200):
        assert process.poll() is None, log
        try:
            rpc('eth_blockNumber')
            get('healthz')
            time.sleep(1.1)
            return
        except OSError:
            time.sleep(.1)
    raise AssertionError('Node did not listen')

def stop():
    global process
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    j['processes'][-1].update(exit_code=process.returncode, finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    process = None
    save()
    assert j['processes'][-1]['exit_code'] == 0

def sample(text, name):
    match = re.search('^' + re.escape(name) + r' (\S+)$', text, re.M)
    assert match, name
    return int(float(match[1]))

def stage(label, expected):
    assert int(rpc('eth_blockNumber'), 16) == expected
    block = rpc('eth_getBlockByNumber', ['latest', False])
    assert int(block['number'], 16) == expected
    finality = rpc('shell_getFinalityInfo')
    # Probe first, so a scrape cannot conceal stale health/readiness fields.
    probes = {name: get(name) for name in ['health', 'healthz', 'ready', 'readyz']}
    for name in ['health', 'healthz']:
        assert probes[name]['status'] == 200
        assert json.loads(probes[name]['body'])['block_height'] == expected, probes[name]
    health = json.loads(probes['healthz']['body'])
    for name in ['ready', 'readyz']:
        body = json.loads(probes[name]['body'])
        ready = expected > 0 and not health['syncing'] and health['production_ready']
        assert probes[name]['status'] == (200 if ready else 503), (health, probes[name])
        assert body['ready'] == ready
        if not ready:
            reason = ('node has not imported any blocks yet' if expected == 0 else
                      'block synchronization is in progress' if health['syncing'] else
                      'block production readiness gate is closed')
            assert body['reason'] == reason
    metrics = get('metrics')
    assert metrics['status'] == 200
    (out / (label + '.prom')).write_text(metrics['body'])
    finalized = int(finality['lastFinalizedBlock'], 16)
    assert sample(metrics['body'], 'shell_block_height') == expected
    assert sample(metrics['body'], 'shell_last_finalized_number') == finalized
    assert sample(metrics['body'], 'shell_finality_lag_blocks') == max(0, expected - finalized)
    assert rpc('eth_getBlockByNumber', ['latest', False]) == block
    j['stages'][label] = {'expected': expected, 'block': block, 'finality': finality, 'probes': probes}
    save()
    return block

try:
    pw = out / 'password'
    pw.write_text(secrets.token_hex(24))
    pw.chmod(0o600)
    cli('key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', out / 'key.json'])
    key = json.loads((out / 'key.json').read_text())
    genesis = {'chain_id': 1337, 'chain_name': 'head-metrics', 'network_type': 'Dev', 'timestamp': int(time.time()),
        'gas_limit': 30000000, 'extra_data': 'head-metrics', 'consensus': {'engine': 'wpoa',
            'authorities': [key['address']], 'authority_pubkeys': ['0x' + key['public_key'].removeprefix('0x')],
            'weights': [3], 'block_time_secs': 1, 'max_future_secs': 60, 'epoch_length': 3},
        'alloc': {key['address']: {'balance': '0x3635c9adc5dea00000'}}, 'boot_nodes': []}
    (out / 'genesis.json').write_text(json.dumps(genesis))
    cli('init', ['--datadir', out / 'data', 'init', '--genesis', out / 'genesis.json', '--network', 'dev', '--chain-id', '1337'])
    start()
    stage('initial', 0)
    genesis_snapshot = rpc('evm_snapshot')
    rpc('evm_mine', [1])
    block1 = stage('mined-one', 1)
    snapshot = rpc('evm_snapshot')
    rpc('evm_mine', [2])
    stage('mined-three', 3)
    assert rpc('evm_mine', [257], rejected=True)['code'] == -32602
    stage('rejected-mine', 3)
    assert rpc('evm_revert', [snapshot]) is True
    assert stage('rewound-one', 1) == block1
    assert rpc('evm_revert', [snapshot]) is False
    stage('rejected-rewind', 1)
    assert rpc('evm_revert', [genesis_snapshot]) is True
    stage('rewound-genesis', 0)
    stop()
    start()
    stage('reopened-genesis', 0)
    rpc('evm_mine', [3])
    head = stage('mined-after-reopen', 3)
    stop()
    start()
    # WPoA dev-mined blocks have no quorum certificate. Existing startup
    # recovery discards that unfinalized suffix; probes must show its new tip.
    stage('recovered-unfinalized', 0)
    recipient = '0x' + '47' * 32
    text = cli('finalized-transfer', ['tx', 'send', '--keystore', out / 'key.json',
        '--password-file', pw, '--to', recipient, '--value', '7', '--chain-id', '1337',
        '--rpc-url', f'http://127.0.0.1:{rpc_port}'])
    tx_hash = re.findall(r'0x[0-9a-f]{64}', text)[-1]
    for _ in range(150):
        receipt = rpc('eth_getTransactionReceipt', [tx_hash])
        fin = rpc('shell_getFinalityInfo')
        if receipt and int(fin['lastFinalizedBlock'], 16) >= int(receipt['blockNumber'], 16):
            break
        time.sleep(.1)
    assert receipt and receipt['status'] == '0x1', receipt
    assert int(fin['lastFinalizedBlock'], 16) >= int(receipt['blockNumber'], 16), fin
    assert int(rpc('eth_getBalance', [recipient, 'latest']), 16) == 7
    assert rpc('eth_getTransactionCount', [key['address'], 'latest']) == '0x1'
    head = stage('finalized-tip', 1)
    j['finalized_receipt'] = receipt
    save()
    stop()
    start()
    assert stage('reopened-finalized-tip', 1) == head
    assert rpc('eth_getTransactionReceipt', [tx_hash]) == receipt
    assert int(rpc('eth_getBalance', [recipient, 'latest']), 16) == 7
    assert rpc('eth_getTransactionCount', [key['address'], 'latest']) == '0x1'
    j['passed'] = True
except BaseException as error:
    j['failure'] = repr(error)
    raise
finally:
    stop()
    j['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({'passed': j.get('passed', False), 'directory': str(out)}))
