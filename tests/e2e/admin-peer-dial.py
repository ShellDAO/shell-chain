#!/usr/bin/env python3
"""Verify admin_addPeer through real transport, signed sync and RocksDB reopen.

Build shell-node with libp2p or set SHELL_NODE_BIN. Python 3 standard library
only. Generates distinct MLDSA65 keys, a private funded Dev1337 genesis and
separate P2P identities. No bootnodes or discovery; every connection is made
through the API. Retains private data and exact receipts in a temp directory.
A successful dial is transient: only synchronized chain state is persisted.
"""
from pathlib import Path
import base64, datetime, hashlib, json, os, re, secrets, socket, struct
import subprocess, tempfile, time, urllib.error, urllib.request

repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', repo / 'target/debug/shell-node')).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-admin-peer-dial-'))
out.chmod(0o700)
j = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
     'directory': str(out), 'commands': [], 'processes': [], 'exchanges': [], 'stages': {}}
processes = {}
rows = {}
ports = set()
token = secrets.token_hex(24)
recipient = '0x' + '47' * 32

def save():
    (out / 'results.json').write_text(json.dumps(j, indent=2) + '\n')

def port():
    while True:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            value = sock.getsockname()[1]
        if value not in ports:
            ports.add(value)
            return value

rpc_ports = [port(), port()]

def cli(label, args):
    value = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=45)
    (out / (label + '.log')).write_text(value.stdout + value.stderr)
    j['commands'].append({'label': label, 'args': list(map(str, args)), 'exit_code': value.returncode})
    save()
    assert value.returncode == 0, (label, value.stderr)
    return value.stdout

def exchange(i, method, params=None, authenticated=True, upgrade=False):
    time.sleep(.05)
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}
    headers = {'Content-Type': 'application/json'}
    if i == 1 and authenticated:
        headers['Authorization'] = 'Bearer ' + token
    if upgrade:
        headers.update({'Connection': 'Upgrade', 'Upgrade': 'websocket',
                        'Sec-WebSocket-Version': '13',
                        'Sec-WebSocket-Key': base64.b64encode(secrets.token_bytes(16)).decode()})
    req = urllib.request.Request(f'http://127.0.0.1:{rpc_ports[i]}',
        None if upgrade else json.dumps(body).encode(), headers)
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, raw = response.status, response.read().decode()
    value = json.loads(raw) if raw.startswith('{') else raw
    j['exchanges'].append({'node': i, 'transport': 'upgrade' if upgrade else 'http',
        'request': body, 'authenticated': i != 1 or authenticated,
        'http_status': status, 'response': value})
    save()
    return status, value

def rpc(i, method, params=None, error=None):
    status, value = exchange(i, method, params)
    assert status == 200, (status, value)
    if error is not None:
        assert value.get('error', {}).get('code') == error, value
        return value['error']
    assert 'error' not in value, value
    return value['result']

def wait(check, seconds=25):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        assert all(p.poll() is None for p in processes.values())
        value = check()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('Business predicate timed out')

def start(i, p2p=True, admin=True):
    args = ['--password-file', str(out / 'password'), 'run', '--datadir', str(out / f'data{i}'),
        '--keystore', str(out / f'key{i}.json'), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb',
        '--rpc-api', 'eth,shell,admin' if admin else 'eth,shell', '--rpc-addr', f'127.0.0.1:{rpc_ports[i]}',
        '--metrics-addr', '127.0.0.1:0', '--node-role', 'validator' if i == 0 else 'prover',
        '--consensus-engine', 'wpoa', '--block-time', '1000', '--max-idle-interval', '1209600000']
    if p2p:
        args += ['--p2p', '--p2p-addr', '127.0.0.1:0']
    if i == 1:
        args += ['--rpc-api-key', token]
    log = out / f'node-{len(j["processes"])}.log'
    with log.open('w') as stream:
        p = subprocess.Popen([str(binary), *args], stdout=stream, stderr=subprocess.STDOUT)
    recorded = list(args)
    if i == 1:
        recorded[recorded.index('--rpc-api-key') + 1] = '<generated token in rpc-token>'
    row = {'node': i, 'pid': p.pid, 'args': recorded, 'log': str(log),
        'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    processes[i], rows[i] = p, row
    j['processes'].append(row)
    save()
    def ready():
        try:
            rpc(i, 'eth_chainId')
            return not p2p or rpc(i, 'admin_nodeInfo')['listenAddr']
        except OSError:
            return False
    wait(ready)

def stop(i):
    p = processes.pop(i, None)
    if p is None:
        return
    if p.poll() is None:
        p.terminate()
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    rows[i].update(exit_code=p.returncode, finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save()
    assert p.returncode == 0, rows[i]

def target(i):
    info = rpc(i, 'admin_nodeInfo')
    address = info['listenAddr']
    return address if '/p2p/' in address else address + '/p2p/' + info['id']

def connected():
    return all(rpc(i, 'admin_nodeInfo')['peerCount'] == 1 for i in [0, 1])

def transfer(label, value, total, nonce):
    text = cli(label, ['tx', 'send', '--keystore', out / 'key0.json', '--password-file', out / 'password',
        '--to', recipient, '--value', str(value), '--chain-id', '1337',
        '--rpc-url', f'http://127.0.0.1:{rpc_ports[0]}'])
    tx_hash = re.findall(r'0x[0-9a-f]{64}', text)[-1]
    def settled():
        for i in [0, 1]:
            receipt = rpc(i, 'eth_getTransactionReceipt', [tx_hash])
            if not receipt:
                return False
            assert receipt['status'] == '0x1', receipt
            if int(rpc(i, 'shell_getFinalityInfo')['lastFinalizedBlock'], 16) < int(receipt['blockNumber'], 16):
                return False
        return True
    wait(settled, 40)
    state = []
    for i in [0, 1]:
        receipt = rpc(i, 'eth_getTransactionReceipt', [tx_hash])
        block = rpc(i, 'eth_getBlockByNumber', [receipt['blockNumber'], False])
        assert int(rpc(i, 'eth_getBalance', [recipient, 'latest']), 16) == total
        assert int(rpc(i, 'eth_getTransactionCount', [keys[0]['address'], 'latest']), 16) == nonce
        state.append({'receipt': receipt, 'block': block})
    assert state[0] == state[1], state
    j['stages'][label] = state[0]
    save()
    return state[0]

class WebSocket:
    """Small RFC6455 text client: masked sends, uncompressed server frames."""
    def __init__(self, listen_port, token=None):
        self.sock = socket.create_connection(('127.0.0.1', listen_port), timeout=4)
        self.file = self.sock.makefile('rb')
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        auth = 'Authorization: Bearer ' + token + '\r\n' if token else ''
        self.sock.sendall((f'GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n{auth}\r\n').encode())
        status = self.file.readline()
        assert b'101' in status, status
        headers = {}
        while True:
            line = self.file.readline()
            if line == b'\r\n':
                break
            name, value = line.decode().split(':', 1)
            headers[name.lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        assert headers['sec-websocket-accept'] == expected
        # Unbuffered frame reads below allow a timeout without poisoning a file buffer.
        self.file.close()
        self.sock.settimeout(4)

    def exact(self, count):
        value = b''
        while len(value) < count:
            chunk = self.sock.recv(count - len(value))
            assert chunk, 'WebSocket closed'
            value += chunk
        return value

    def send(self, body):
        raw = json.dumps(body).encode()
        mask = secrets.token_bytes(4)
        n = len(raw)
        length = bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack('!H', n)
        self.sock.sendall(b'\x81' + length + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(raw)))
        j['exchanges'].append({'transport': 'ws', 'request': body})
        save()

    def receive(self):
        header = self.exact(2)
        assert header[0] == 0x81 and not header[1] & 0x80, header
        n = header[1] & 127
        if n == 126:
            n = struct.unpack('!H', self.exact(2))[0]
        if n == 127:
            n = struct.unpack('!Q', self.exact(8))[0]
        value = json.loads(self.exact(n))
        j['exchanges'].append({'transport': 'ws', 'response': value})
        save()
        return value

    def silence(self):
        self.sock.settimeout(.25)
        try:
            unexpected = self.sock.recv(1)
            raise AssertionError(('Unexpected notification response/close', unexpected))
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(4)

    def close(self):
        self.sock.close()

try:
    password = out / 'password'
    password.write_text(secrets.token_hex(24))
    password.chmod(0o600)
    (out / 'rpc-token').write_text(token)
    (out / 'rpc-token').chmod(0o600)
    keys = []
    for i in [0, 1]:
        cli(f'key{i}', ['--password-file', password, 'key', 'generate', '--algorithm', 'mldsa65', '--output', out / f'key{i}.json'])
        keys.append(json.loads((out / f'key{i}.json').read_text()))
    assert keys[0]['address'] != keys[1]['address']
    genesis = {'chain_id': 1337, 'chain_name': 'admin-dial', 'network_type': 'Dev', 'timestamp': int(time.time()),
        'gas_limit': 30000000, 'extra_data': 'admin-dial', 'consensus': {'engine': 'wpoa',
            'authorities': [keys[0]['address']], 'authority_pubkeys': ['0x' + keys[0]['public_key'].removeprefix('0x')],
            'weights': [3], 'block_time_secs': 1, 'max_future_secs': 60, 'epoch_length': 100},
        'alloc': {keys[0]['address']: {'balance': '0x3635c9adc5dea00000'}}, 'boot_nodes': []}
    (out / 'genesis.json').write_text(json.dumps(genesis))
    for i in [0, 1]:
        cli(f'init{i}', ['--datadir', out / f'data{i}', 'init', '--genesis', out / 'genesis.json', '--network', 'dev', '--chain-id', '1337'])
        start(i)
    identities = [rpc(i, 'admin_nodeInfo')['id'] for i in [0, 1]]
    assert identities[0] != identities[1]
    assert all(rpc(i, 'admin_nodeInfo')['peerCount'] == 0 for i in [0, 1])
    remote = target(0)
    assert exchange(1, 'admin_addPeer', [remote], authenticated=False)[0] == 401
    assert exchange(1, 'admin_addPeer', [remote], authenticated=False, upgrade=True)[0] == 401
    for bad in ['', 'not-a-multiaddr', 'x' * 4097, remote]:
        rpc(0, 'admin_addPeer', [bad], error=-32602)
    rpc(0, 'admin_addPeer', [False], error=-32602)
    assert all(rpc(i, 'admin_nodeInfo')['peerCount'] == 0 for i in [0, 1])
    assert rpc(0, 'admin_addPeer', [target(1)]) is True
    wait(connected)
    assert rpc(0, 'admin_addPeer', [target(1)]) is False
    ws = WebSocket(rpc_ports[1], token)
    try:
        ws.send({'jsonrpc': '2.0', 'id': 2, 'method': 'admin_addPeer', 'params': [target(0)]})
        assert ws.receive()['result'] is False
    finally:
        ws.sock.close()
    time.sleep(1.5)
    first = transfer('http-connected-transfer', 7, 7, 1)
    for i in [1, 0]:
        stop(i)
    for i in [0, 1]:
        start(i)
        assert rpc(i, 'admin_nodeInfo')['id'] == identities[i]
        assert rpc(i, 'admin_nodeInfo')['peerCount'] == 0
        assert rpc(i, 'eth_getTransactionReceipt', [first['receipt']['transactionHash']]) == first['receipt']
        assert rpc(i, 'eth_getBlockByNumber', [first['receipt']['blockNumber'], False]) == first['block']
        assert int(rpc(i, 'eth_getBalance', [recipient, 'latest']), 16) == 7
    ws = WebSocket(rpc_ports[1], token)
    try:
        ws.send({'jsonrpc': '2.0', 'id': 3, 'method': 'admin_addPeer', 'params': [target(0)]})
        assert ws.receive()['result'] is True
    finally:
        ws.sock.close()
    wait(connected)
    time.sleep(1.5)
    transfer('ws-reconnected-transfer', 11, 18, 2)
    for i in [1, 0]:
        stop(i)
    start(0, p2p=False)
    rpc(0, 'admin_addPeer', [remote], error=-32003)
    assert int(rpc(0, 'eth_getBalance', [recipient, 'latest']), 16) == 18
    assert int(rpc(0, 'eth_getTransactionCount', [keys[0]['address'], 'latest']), 16) == 2
    stop(0)
    start(0, p2p=False, admin=False)
    rpc(0, 'admin_addPeer', [remote], error=-32601)
    j['passed'] = True
except BaseException as error:
    j['failure'] = repr(error)
    raise
finally:
    for i in list(processes):
        stop(i)
    j['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({'passed': j.get('passed', False), 'directory': str(out)}))
