#!/usr/bin/env python3
"""Verify live consensus roster metrics through real governance, import and restart.

Build shell-node with libp2p or set SHELL_NODE_BIN. Python 3 standard library only.
Creates two fresh MLDSA65 test keys, private Dev1337 genesis/RocksDB directories
and loopback listeners. Retains data/keys and exact receipts for inspection.
One validator signs; the other process follows as a prover-role follower throughout.
"""
from pathlib import Path
import datetime, json, os, re, secrets, socket, subprocess, tempfile, time, urllib.request
repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', repo / 'target/debug/shell-node')).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-roster-metrics-'))
out.chmod(0o700)
j = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'directory': str(out),
     'commands': [], 'processes': [], 'rpc': [], 'stages': {}, 'scope': 'Local Dev1337, explicit epoch3 and 1s blocks; no public activation/scale claim.'}
nodes = {}

def save():
    (out / 'results.json').write_text(json.dumps(j, indent=2) + '\n')

def cli(label, args):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=40)
    (out / (label + '.log')).write_text(result.stdout + result.stderr)
    j['commands'].append({'label': label, 'args': list(map(str, args)), 'exit_code': result.returncode})
    save()
    assert result.returncode == 0, (label, result.stderr)
    return result.stdout

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

ports = {n: {'rpc': port(), 'metrics': port()} for n in ['A', 'B']}

def rpc(name, method, params=None):
    request = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}
    req = urllib.request.Request(f'http://127.0.0.1:{ports[name]["rpc"]}', json.dumps(request).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as response:
        value = json.load(response)
    j['rpc'].append({'node': name, 'request': request, 'response': value})
    save()
    assert 'error' not in value, value
    return value['result']

def until(check, seconds=45):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        assert all(p.poll() is None for p, _ in nodes.values())
        try:
            value = check()
            if value:
                return value
        except OSError:
            pass
        time.sleep(.15)
    raise AssertionError('Acceptance predicate timed out')

def start(name, boot=None):
    args = ['--password-file', str(out / 'password'), 'run', '--datadir', str(out / name),
            '--keystore', str(out / (name + '.json')), '--network', 'dev', '--chain-id', '1337',
            '--db', 'rocksdb', '--consensus-engine', 'wpoa', '--block-time', '1000',
            '--rpc-addr', f'127.0.0.1:{ports[name]["rpc"]}',
            '--metrics-addr', f'127.0.0.1:{ports[name]["metrics"]}', '--max-idle-interval', '1209600000',
            '--p2p', '--p2p-addr', '127.0.0.1:0', '--log-level', 'info', '--node-role', 'validator' if name == 'A' else 'prover']
    if boot:
        args += ['--bootnode', boot]
    log = out / f'{name}-{len(j["processes"])}.log'
    with log.open('w') as stream:
        process = subprocess.Popen([str(binary), *args], stdout=stream, stderr=subprocess.STDOUT)
    row = {'name': name, 'pid': process.pid, 'args': args, 'log': str(log),
           'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    nodes[name] = process, row
    j['processes'].append(row)
    save()
    until(lambda: rpc(name, 'eth_blockNumber'))
    return until(lambda: (re.search(r'Listening on (/ip4/127\.0\.0\.1/tcp/\d+/p2p/[A-Za-z0-9]+)', log.read_text()) or [None, None])[1])

def stop_all():
    for name, (process, row) in list(nodes.items()):
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        row.update(exit_code=process.returncode, finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        del nodes[name]
        save()
        assert process.returncode == 0, row

def collect(name, label):
    with urllib.request.urlopen(f'http://127.0.0.1:{ports[name]["metrics"]}/metrics', timeout=5) as response:
        text = response.read().decode()
    (out / (label + '-' + name + '.prom')).write_text(text)
    count = re.search(r'^shell_validator_active_count (\S+)$', text, re.M)
    weights = {a: float(w) for a, w in re.findall(r'^shell_validator_weight\{validator="([^"]+)"\} (\S+)$', text, re.M)}
    assert count, text
    return int(float(count[1])), weights

receipts = []

def committed(tx):
    receipt = until(lambda: rpc('A', 'eth_getTransactionReceipt', [tx]))
    assert receipt['status'] == '0x1', receipt
    until(lambda: int(rpc('A', 'shell_getFinalityInfo')['lastFinalizedBlock'], 16) >= int(receipt['blockNumber'], 16))
    receipts.append((tx, receipt))
    return int(receipt['blockNumber'], 16)

def transfer(label, sender="A", value="1"):
    recipient = "B" if sender == "A" else "A"
    text = cli(label, ['tx', 'send', '--keystore', out / (sender + '.json'), '--password-file', out / 'password',
        '--to', keys[recipient]['address'], '--value', value, '--chain-id', '1337',
        '--rpc-url', f'http://127.0.0.1:{ports["A"]["rpc"]}'])
    return committed(re.findall(r'0x[0-9a-f]{64}', text)[-1])

def stage(label, expected, height):
    for name in nodes:
        until(lambda: int(rpc(name, 'eth_blockNumber'), 16) == height)
        assert collect(name, label) == (sum(w > 0 for w in expected.values()), expected), (name, label, collect(name, label), expected)
        # Repeated scrapes retain the same count and complete label set.
        assert collect(name, label + '-again') == (sum(w > 0 for w in expected.values()), expected)
    blocks = {name: rpc(name, 'eth_getBlockByNumber', [hex(height), False]) for name in nodes}
    assert len({b['hash'] for b in blocks.values()}) == 1
    j['stages'][label] = {'expected': expected, 'height': height, 'blocks': blocks}
    save()

try:
    pw = out / 'password'
    pw.write_text(secrets.token_hex(24))
    pw.chmod(0o600)
    keys = {}
    for name in ['A', 'B']:
        cli('key-' + name, ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', out / (name + '.json')])
        keys[name] = json.loads((out / (name + '.json')).read_text())
    a, b = keys['A']['address'], keys['B']['address']
    genesis = {'chain_id': 1337, 'chain_name': 'roster-metrics', 'network_type': 'Dev',
        'timestamp': int(time.time()), 'gas_limit': 30000000, 'extra_data': 'roster-metrics',
        'consensus': {'engine': 'wpoa', 'authorities': [a], 'authority_pubkeys': ['0x' + keys['A']['public_key'].removeprefix('0x')],
            'weights': [3], 'block_time_secs': 1, 'max_future_secs': 60, 'epoch_length': 3},
        'alloc': {a: {'balance': '0x3635c9adc5dea00000'}, b: {'balance': '0x3635c9adc5dea00000'}}, 'boot_nodes': []}
    (out / 'genesis.json').write_text(json.dumps(genesis))
    for name in ['A', 'B']:
        cli('init-' + name, ['--datadir', out / name, 'init', '--genesis', out / 'genesis.json', '--network', 'dev', '--chain-id', '1337'])
    boot = start('A')
    start('B', boot)
    until(lambda: all(int(rpc(n, 'net_peerCount'), 16) > 0 for n in nodes))
    stage('initial', {a: 3}, 0)
    # A joining validator must first register its real key via a signed transaction.
    assert transfer('register-joining-key', sender='B') == 1
    assert committed(rpc('A', 'shell_proposeAddValidator', [b])) == 2
    stage('pending-add', {a: 3}, 2)
    assert transfer('add-boundary-3') == 3
    stage('added', {a: 3, b: 1}, 3)
    assert committed(rpc('A', 'shell_proposeRemoveValidator', [b])) == 4
    stage('pending-remove', {a: 3, b: 1}, 4)
    assert transfer('remove-boundary-5') == 5
    assert transfer('remove-boundary-6') == 6
    stage('removed', {a: 3}, 6)
    assert committed(rpc('A', 'shell_proposeSetValidatorWeight', [a, 5])) == 7
    stage('pending-weight', {a: 3}, 7)
    assert transfer('weight-boundary-8') == 8
    assert transfer('weight-boundary-9') == 9
    stage('weighted', {a: 5}, 9)
    final_height = 9
    until(lambda: all(int(rpc(n, 'shell_getFinalityInfo')['lastFinalizedBlock'], 16) >= final_height for n in nodes))
    before = {n: {'balance': rpc(n, 'eth_getBalance', [b, 'latest']), 'nonce': rpc(n, 'eth_getTransactionCount', [a, 'latest']),
        'head': rpc(n, 'eth_getBlockByNumber', ['latest', False]), 'finality': rpc(n, 'shell_getFinalityInfo')} for n in nodes}
    assert before['A']['balance'] == before['B']['balance']
    assert before['A']['nonce'] == before['B']['nonce']
    stop_all()
    boot = start('A')
    start('B', boot)
    stage('reopened', {a: 5}, final_height)
    for name in nodes:
        assert rpc(name, 'eth_getBalance', [b, 'latest']) == before[name]['balance']
        assert rpc(name, 'eth_getTransactionCount', [a, 'latest']) == before[name]['nonce']
        assert rpc(name, 'eth_getBlockByNumber', ['latest', False]) == before[name]['head']
        assert rpc(name, 'shell_getFinalityInfo') == before[name]['finality']
        for tx, receipt in receipts:
            assert rpc(name, 'eth_getTransactionReceipt', [tx]) == receipt
    j.update(passed=True, receipts=receipts, before_restart=before)
except BaseException as error:
    j['failure'] = repr(error)
    raise
finally:
    stop_all()
    j['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({'passed': j.get('passed', False), 'directory': str(out)}))
