#!/usr/bin/env python3
"""Check next-proposer RPC against signed WPoA blocks, view change and restart.

Run with Python 3 after building shell-node with libp2p. SHELL_NODE_BIN selects
the node under test; PEER_NODE_BIN optionally selects a compatible peer binary.
Four fresh ML-DSA-65 authorities use isolated dev RocksDB databases and ports.
Private test data and receipts are retained in the printed temporary directory.
"""
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request

repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', repo / 'target/debug/shell-node')).resolve()
peer_binary = Path(os.environ.get('PEER_NODE_BIN', binary)).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-consensus-proposer-'))
out.chmod(0o700)
result = {'directory': str(out), 'commands': [], 'processes': [], 'blocks': [],
          'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'binaries': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in {binary, peer_binary}}}
nodes, ports, keys, addresses = {}, {}, {}, {}
recipient = '0x' + secrets.token_hex(32)
result['recipient'] = recipient


def save():
    (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')


def run(label, args):
    command = [str(binary), *map(str, args)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out / (label + '.log')).write_text(completed.stdout + completed.stderr)
    result['commands'].append({'command': command, 'exit_code': completed.returncode})
    save()
    assert completed.returncode == 0, (label, completed.stderr)
    return completed.stdout


def rpc(name, method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                       'params': params or []}).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{ports[name]}', body,
                                     {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=4) as response:
        value = json.load(response)
    assert 'error' not in value, (method, value)
    return value['result']


def wait(label, check, timeout=40, interval=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name, (process, row) in nodes.items():
            assert process.poll() is None, (name, row)
        try:
            value = check()
            if value:
                return value
        except (OSError, TimeoutError):
            pass
        time.sleep(interval)
    raise AssertionError('Timed out: ' + label)


def stop(name):
    process, row = nodes.pop(name)
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    row.update(exit_code=process.returncode,
               finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save()
    assert process.returncode == 0, row


def start(name, boot=None):
    executable = binary if name == 'A' else peer_binary
    args = ['run', '--datadir', out / name, '--keystore', keys[name],
            '--password-file', password, '--rpc-addr', f'127.0.0.1:{ports[name]}',
            '--metrics-addr', '127.0.0.1:0', '--p2p', '--p2p-addr', '127.0.0.1:0',
            '--network', 'dev', '--chain-id', '1337', '--consensus-engine', 'wpoa',
            '--node-role', 'validator', '--db', 'rocksdb', '--storage-profile', 'full',
            '--max-idle-interval', '1209600000', '--block-time', '2000',
            '--log-level', 'debug']
    if boot:
        args += ['--bootnode', boot]
    command = [str(executable), *map(str, args)]
    log = out / f'{name}-{len(result["processes"])}.log'
    with log.open('w') as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
    row = {'name': name, 'pid': process.pid, 'command': command, 'log': str(log)}
    result['processes'].append(row)
    nodes[name] = (process, row)
    save()
    wait(name + ' RPC', lambda: rpc(name, 'shell_getNodeInfo'), timeout=20)
    return log


def multiaddr(log):
    match = re.search(r'Listening on (/ip4/127\.0\.0\.1/tcp/\d+/p2p/[a-zA-Z0-9]+)',
                      log.read_text())
    return match.group(1) if match else None


def send(label):
    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(body)
            if request.get('method') == 'eth_sendRawTransaction':
                (out / (label + '-signed-input.json')).write_text(json.dumps(request))
            target = urllib.request.Request(f'http://127.0.0.1:{ports["A"]}', body,
                                            {'Content-Type': 'application/json'})
            with urllib.request.urlopen(target, timeout=8) as response:
                value = response.read()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(value)

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Proxy)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        text = run(label, ['tx', 'send', '--keystore', keys['A'],
                           '--password-file', password, '--to', recipient,
                           '--value', '1', '--chain-id', '1337', '--rpc-url',
                           f'http://127.0.0.1:{server.server_port}'])
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert (out / (label + '-signed-input.json')).exists()
    return re.findall(r'0x[0-9a-f]{64}', text)[-1]


def finalized(tx):
    receipt = rpc('A', 'eth_getTransactionReceipt', [tx])
    if receipt and int(rpc('A', 'shell_getFinalityInfo')['lastFinalizedBlock'], 16) >= int(receipt['blockNumber'], 16):
        return receipt
    return None


def snapshot(name):
    return {'head': rpc(name, 'eth_getBlockByNumber', ['latest', False]),
            'balance': rpc(name, 'eth_getBalance', [recipient, 'latest']),
            'nonce': rpc(name, 'eth_getTransactionCount', [addresses['A'], 'latest'])}


def accept(tx, height, expected, prediction):
    receipt = wait('finalized original transaction', lambda: finalized(tx))
    assert int(receipt['status'], 16) == 1 and int(receipt['blockNumber'], 16) == height
    block = rpc('A', 'eth_getBlockByNumber', [receipt['blockNumber'], False])
    assert prediction['current_proposer'] == block['miner'] == addresses[expected]
    assert prediction['block_number'] == height - 1
    proof = rpc('A', 'shell_finalityProof', [block['hash']])
    assert len(proof['certificate']) >= 3
    state = snapshot('A')
    assert int(state['balance'], 16) == 10**21 + height
    assert int(state['nonce'], 16) == height
    for name in nodes:
        wait(name + ' imports original transaction', lambda n=name:
             rpc(n, 'eth_getTransactionReceipt', [tx]) == receipt and
             int(rpc(n, 'shell_getFinalityInfo')['lastFinalizedBlock'], 16) >= height)
        assert snapshot(name) == state
    result['blocks'].append({'transaction': tx, 'prediction': prediction,
                             'receipt': receipt, 'block': block, 'proof': proof})
    save()
    return state


password = out / 'password'
password.write_text(secrets.token_hex(24))
password.chmod(0o600)
try:
    for name in 'ABCD':
        keys[name] = out / (name + '.json')
        run('key-' + name, ['key', 'generate', '--algorithm', 'mldsa65',
                            '--output', keys[name], '--password-file', password])
        text = run('inspect-' + name, ['key', 'inspect', keys[name]])
        addresses[name] = re.search(r'Address:\s*(0x[0-9a-f]{64})', text).group(1)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            ports[name] = sock.getsockname()[1]
    result['addresses'] = addresses
    genesis = {'chain_id': 1337, 'chain_name': 'consensus-proposer', 'network_type': 'Dev',
               'timestamp': int(time.time()) - 120, 'gas_limit': 50000000,
               'extra_data': 'consensus-proposer', 'boot_nodes': [],
               'alloc': {a: {'balance': '0x3635c9adc5dea00000'} for a in [*addresses.values(), recipient]},
               'consensus': {'engine': 'wpoa', 'authorities': list(addresses.values()),
                             'authority_pubkeys': ['0x' + json.loads(keys[n].read_text())['public_key'].removeprefix('0x') for n in keys],
                             'weights': [1, 1, 1, 1], 'stakes': [], 'block_time_secs': 2,
                             'max_future_secs': 300, 'epoch_length': 0}}
    for name in keys:
        (out / name).mkdir()
        (out / name / 'genesis.json').write_text(json.dumps(genesis))
    log_a = start('A')
    boot_a = wait('A multiaddress', lambda: multiaddr(log_a))
    log_c = start('C', boot_a)
    boot_c = wait('C multiaddress', lambda: multiaddr(log_c))
    start('B', boot_a)
    start('D', boot_a)
    wait('four connected authorities', lambda: all(
        int(rpc(n, 'eth_blockNumber'), 16) == 0 and
        int(rpc(n, 'net_peerCount'), 16) > 0 for n in nodes))
    time.sleep(2)
    guide = (repo / 'docs/JSON_RPC_API.md').read_text().split('### shell_consensusInfo\n')[1]
    original = guide.split('```bash\n')[1].split('```')[0]
    command = original.replace('http://localhost:8545', f'http://127.0.0.1:{ports["A"]}')
    documented = subprocess.run(['sh', '-c', command], capture_output=True, text=True,
                                timeout=10, env={**os.environ, 'NO_PROXY': '127.0.0.1,localhost'})
    assert documented.returncode == 0, documented.stderr
    result['documented_request'] = json.loads(documented.stdout)
    assert result['documented_request']['result'] == rpc('A', 'shell_consensusInfo')
    for height, proposer in enumerate('BCDA', 1):
        state_before_query = snapshot('A')
        prediction = rpc('A', 'shell_consensusInfo')
        assert snapshot('A') == state_before_query, 'Read-only query changed committed state'
        assert prediction['current_proposer'] == addresses[proposer]
        accept(send('transfer-' + str(height)), height, proposer, prediction)
    assert not any('view-change quorum reached' in Path(row['log']).read_text()
                   for _, row in nodes.values()), 'Base schedule requires view zero'
    stop('B')  # Three of four genuine validators remain to certify view change.
    prediction = rpc('A', 'shell_consensusInfo')
    assert prediction['block_number'] == 4 and prediction['current_proposer'] == addresses['B']
    tx = send('view-change-transfer')
    result['view_samples'] = [prediction]

    def rotated():
        sample = rpc('A', 'shell_consensusInfo')
        if sample != result['view_samples'][-1]:
            result['view_samples'].append(sample)
            save()
        assert sample['block_number'] == 4, 'Missed same-height rotated prediction'
        return sample if sample['current_proposer'] == addresses['C'] else None

    prediction = wait('same-height certified proposer rotation', rotated)
    before = accept(tx, 5, 'C', prediction)
    assert any('view-change quorum reached' in Path(row['log']).read_text()
               for _, row in nodes.values())
    stop('A')
    start('A', boot_c)
    wait('physical restart preserves committed state', lambda: snapshot('A') == before)
    for row in result['blocks']:
        assert rpc('A', 'eth_getTransactionReceipt', [row['transaction']]) == row['receipt']
    after = rpc('A', 'shell_consensusInfo')
    assert after['block_number'] == 5 and after['current_proposer'] == addresses['C']
    result['reopened'] = {'state': snapshot('A'), 'consensus': after}
    result['passed'] = True
except BaseException as error:
    result['failure'] = repr(error)
    raise
finally:
    failures = []
    for name in list(nodes):
        try:
            stop(name)
        except BaseException as error:
            failures.append(repr(error))
    result['cleanup_failures'] = failures
    result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({'passed': result.get('passed', False), 'directory': str(out)}))
    assert not failures, failures
