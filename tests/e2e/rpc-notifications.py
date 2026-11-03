#!/usr/bin/env python3
"""Exercise JSON-RPC notifications using real local state and signed transactions.

Build shell-node with libp2p, or set SHELL_NODE_BIN. Python 3 standard library
only. Creates its own keys/genesis/private RocksDB data and loopback listeners.
Retains data and exact wire receipts in a private temporary directory. The CLI
is used only to create a genuinely signed input: a local capture endpoint stops
submission with a deliberate error, before the script sends that input itself.
--expect-ignored reproduces the pre-fix defect, then submits the identical raw
input with an id to prove it is valid; it does not qualify notification support.
"""
from pathlib import Path
import argparse, base64, datetime, hashlib, http.server, json, os, re, secrets
import socket, struct, subprocess, tempfile, threading, time, urllib.error, urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--expect-ignored', action='store_true')
options = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', repo / 'target/debug/shell-node')).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-rpc-notifications-'))
out.chmod(0o700)
j = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
     'directory': str(out), 'mode': 'original-defect' if options.expect_ignored else 'acceptance',
     'processes': [], 'commands': [], 'exchanges': [], 'stages': {}}
process = None

def save():
    (out / 'results.json').write_text(json.dumps(j, indent=2) + '\n')

def cli(label, args, expected=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=45)
    (out / (label + '.log')).write_text(result.stdout + result.stderr)
    j['commands'].append({'label': label, 'args': list(map(str, args)), 'exit_code': result.returncode})
    save()
    assert result.returncode == expected, (label, result.stderr)
    return result.stdout

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

http_port, ws_port = port(), port()
address = '0x' + '47' * 32

def exchange(body, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(f'http://127.0.0.1:{http_port}', json.dumps(body).encode(), headers)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, raw = response.status, response.read().decode()
    j['exchanges'].append({'transport': 'http', 'request': body, 'http_status': status, 'response': raw,
                           'authenticated': token is not None})
    save()
    return status, json.loads(raw) if raw else None

def request(method, params=None, token=None):
    status, value = exchange({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}, token)
    assert status == 200 and 'error' not in value, (method, status, value)
    return value['result']

def notification(method, params=None, token=None):
    return exchange({'jsonrpc': '2.0', 'method': method, 'params': params or []}, token)

def balance(token=None):
    return int(request('eth_getBalance', [address, 'latest'], token), 16)

def wait(check, seconds=20):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        assert process.poll() is None
        value = check()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('Business predicate timed out')

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
    j['processes'][-1].update(exit_code=process.returncode,
        finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    process = None
    save()
    assert j['processes'][-1]['exit_code'] == 0

def start(dedicated=False, token=None):
    global process
    args = ['--password-file', str(out / 'password'), 'run', '--datadir', str(out / 'data'),
            '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb', '--keystore', str(out / 'key.json'),
            '--rpc-api', 'eth,shell,evm', '--rpc-addr', f'127.0.0.1:{http_port}',
            '--metrics-addr', '127.0.0.1:0', '--p2p', '--p2p-addr', '127.0.0.1:0',
            '--consensus-engine', 'wpoa', '--block-time', '1000', '--max-idle-interval', '1209600000']
    if dedicated:
        args += ['--ws', '--ws-port', str(ws_port)]
    if token:
        args += ['--rpc-api-key', token, '--rpc-rate-limit', '2']
    log = out / f'node-{len(j["processes"])}.log'
    with log.open('w') as stream:
        process = subprocess.Popen([str(binary), *args], stdout=stream, stderr=subprocess.STDOUT)
    recorded = list(args)
    if token:
        recorded[recorded.index('--rpc-api-key') + 1] = '<generated token in rpc-token>'
    j['processes'].append({'pid': process.pid, 'args': recorded, 'log': str(log),
                           'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    save()
    for _ in range(200):
        assert process.poll() is None, log
        try:
            with socket.create_connection(('127.0.0.1', http_port), timeout=.2):
                return
        except OSError:
            time.sleep(.1)
    raise AssertionError('RPC did not listen')

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

def ws_checks(listen_port):
    ws = WebSocket(listen_port)
    try:
        def call(method, params=None, id_value=8):
            ws.send({'jsonrpc': '2.0', 'id': id_value, 'method': method, 'params': params or []})
            result = ws.receive()
            assert result['id'] == id_value and 'error' not in result, result
            return result['result']
        ws.send({'jsonrpc': '2.0', 'method': 'shell_setBalance', 'params': [address, '0x8d']})
        ws.silence()
        assert int(call('eth_getBalance', [address, 'latest']), 16) == 141
        ws.send([{'jsonrpc': '2.0', 'method': 'shell_setBalance', 'params': [address, '0x97']},
                 {'jsonrpc': '2.0', 'method': 'eth_chainId', 'id': 17},
                 {'jsonrpc': '2.0', 'method': 'unknown'}])
        assert ws.receive() == [{'jsonrpc': '2.0', 'id': 17, 'result': '0x539'}]
        assert int(call('eth_getBalance', [address, 'latest']), 16) == 151
        ws.send([{'jsonrpc': '2.0', 'method': 'shell_setBalance', 'params': [address, '0xa1']},
                 {'jsonrpc': '2.0', 'method': 'shell_setBalance', 'params': [address, '0xab']}])
        ws.silence()
        assert int(call('eth_getBalance', [address, 'latest']), 16) == 171
        for method, params in [('unknown', []), ('shell_setBalance', []), ('shell_setBalance', [address, 'invalid'])]:
            ws.send({'jsonrpc': '2.0', 'method': method, 'params': params})
        ws.silence()
        assert int(call('eth_getBalance', [address, 'latest']), 16) == 171
        ws.send({'jsonrpc': '2.0', 'method': 'shell_setBalance', 'params': [address, '0x3e7'], 'id': {}})
        rejected = ws.receive()
        assert rejected['error']['code'] == -32600
        assert int(call('eth_getBalance', [address, 'latest']), 16) == 171
        assert call('shell_setBalance', [address, '0xb5'], None) is True
        ws.send({'jsonrpc': '2.0', 'method': 'eth_subscribe', 'params': ['newPendingTransactions']})
        ws.silence()
        sub = call('eth_subscribe', ['newPendingTransactions'])
        ws.send({'jsonrpc': '2.0', 'method': 'eth_unsubscribe', 'params': [sub]})
        ws.silence()
        assert call('eth_unsubscribe', [sub]) is False
        assert int(call('eth_getBalance', [address, 'latest']), 16) == 181
    finally:
        ws.close()

try:
    pw = out / 'password'
    pw.write_text(secrets.token_hex(24))
    pw.chmod(0o600)
    cli('key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', out / 'key.json'])
    key = json.loads((out / 'key.json').read_text())
    genesis = {'chain_id': 1337, 'chain_name': 'notification-execution', 'network_type': 'Dev',
        'timestamp': int(time.time()), 'gas_limit': 30000000, 'extra_data': 'notification-execution',
        'consensus': {'engine': 'wpoa', 'authorities': [key['address']],
            'authority_pubkeys': ['0x' + key['public_key'].removeprefix('0x')], 'weights': [1],
            'block_time_secs': 1, 'max_future_secs': 60, 'epoch_length': 0},
        'alloc': {key['address']: {'balance': '0x3635c9adc5dea00000'}}, 'boot_nodes': []}
    (out / 'genesis.json').write_text(json.dumps(genesis))
    cli('init', ['--datadir', out / 'data', 'init', '--genesis', out / 'genesis.json', '--chain-id', '1337', '--network', 'dev'])
    start()
    assert balance() == 0
    assert notification('shell_setBalance', [address, '0x7b']) == (200, None)
    assert balance() == (0 if options.expect_ignored else 123)
    if options.expect_ignored:
        assert request('shell_setBalance', [address, '0x7b']) is True
    assert balance() == 123
    # Capture a real CLI-signed input without submitting it or returning fake success.
    captured = {}
    class Capture(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            value = json.loads(body)
            if value['method'] == 'eth_sendRawTransaction':
                captured.update(value)
                raw = json.dumps({'jsonrpc': '2.0', 'id': value['id'], 'error': {'code': -32000, 'message': 'test input captured, not submitted'}}).encode()
            else:
                req = urllib.request.Request(f'http://127.0.0.1:{http_port}', body, {'Content-Type': 'application/json'})
                raw = urllib.request.urlopen(req, timeout=5).read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *args):
            pass
    capture = http.server.HTTPServer(('127.0.0.1', 0), Capture)
    thread = threading.Thread(target=capture.serve_forever)
    thread.start()
    try:
        cli('capture-signed', ['tx', 'send', '--keystore', out / 'key.json', '--password-file', pw,
             '--to', address, '--value', '7', '--chain-id', '1337', '--rpc-url', f'http://127.0.0.1:{capture.server_port}'], expected=1)
    finally:
        capture.shutdown()
        thread.join()
        capture.server_close()
    assert captured['method'] == 'eth_sendRawTransaction'
    (out / 'signed-input.json').write_text(json.dumps(captured, indent=2))
    raw = captured['params'][0]
    tampered = raw[:-2] + f'{int(raw[-2:], 16) ^ 1:02x}'
    assert notification('eth_sendRawTransaction', [tampered]) == (200, None)
    time.sleep(.25)
    assert balance() == 123
    assert request('eth_getTransactionCount', [key['address'], 'latest']) == '0x0'
    assert notification('eth_sendRawTransaction', [raw]) == (200, None)
    if options.expect_ignored:
        time.sleep(2.2)
        assert balance() == 123
        assert request('eth_getTransactionCount', [key['address'], 'latest']) == '0x0'
        j['stages']['original_signed_notification_ignored'] = True
        tx_hash = request('eth_sendRawTransaction', [raw])
    else:
        wait(lambda: balance() == 130)
        block = request('eth_getBlockByNumber', ['latest', False])
        # Blocks also expose protocol system transactions. Select the actual
        # user transfer by its independently chosen sender/recipient/value.
        candidates = [request('eth_getTransactionByHash', [h]) for h in block['transactions']]
        matches = [tx for tx in candidates if tx.get('from') == key['address']
                   and tx.get('to') == address and tx.get('value') == '0x7']
        assert len(matches) == 1, candidates
        tx_hash = matches[0]['hash']
    receipt = wait(lambda: request('eth_getTransactionReceipt', [tx_hash]))
    assert receipt['status'] == '0x1' and receipt['to'] == address
    assert balance() == 130
    assert request('eth_getTransactionCount', [key['address'], 'latest']) == '0x1'
    tx = request('eth_getTransactionByHash', [tx_hash])
    assert tx['from'] == key['address'] and tx['to'] == address and tx['value'] == '0x7' and tx['nonce'] == '0x0'
    finality = wait(lambda: (value if int(value['lastFinalizedBlock'], 16) >= int(receipt['blockNumber'], 16) else None) if (value := request('shell_getFinalityInfo')) else None)
    head = request('eth_getBlockByNumber', ['latest', False])
    j['stages']['signed_transaction'] = {'hash': tx_hash, 'receipt': receipt, 'transaction': tx, 'head': head, 'finality': finality}
    save()
    if not options.expect_ignored:
        ws_checks(http_port)
        j['stages']['shared_ws'] = True
    stop()
    start(dedicated=True)
    assert request('eth_getTransactionReceipt', [tx_hash]) == receipt
    assert request('eth_getTransactionCount', [key['address'], 'latest']) == '0x1'
    assert request('eth_getBlockByNumber', [head['number'], False]) == head
    if options.expect_ignored:
        assert balance() == 130
        j['stages']['control_reopen'] = True
    else:
        # Reopen the canonical transfer state; dev setters above were unmined.
        assert balance() == 130
        ws_checks(ws_port)
        j['stages']['dedicated_ws_reopen'] = True
    stop()
    if not options.expect_ignored:
        token = secrets.token_hex(24)
        token_file = out / 'rpc-token'
        token_file.write_text(token)
        token_file.chmod(0o600)
        start(dedicated=True, token=token)
        assert notification('shell_setBalance', [address, '0x3e7'])[0] == 401
        assert balance(token) == 130
        assert notification('shell_setBalance', [address, '0xbf'], token) == (200, None)
        assert notification('shell_setBalance', [address, '0xc9'], token)[0] == 429
        time.sleep(1.1)
        assert balance(token) == 191
        time.sleep(1.1)
        ws = WebSocket(ws_port, token)
        try:
            ws.send([{'jsonrpc': '2.0', 'method': 'shell_setBalance', 'params': [address, hex(v)]} for v in [211, 221, 231]])
            ws.silence()
            time.sleep(1.1)
            ws.send({'jsonrpc': '2.0', 'method': 'eth_getBalance', 'params': [address, 'latest'], 'id': 50})
            assert ws.receive() == {'jsonrpc': '2.0', 'id': 50, 'result': hex(221)}
        finally:
            ws.close()
        time.sleep(1.1)
        status, missing = exchange({'jsonrpc': '2.0', 'id': 9, 'method': 'web3_clientVersion'})
        assert status == 401
        status, missing = exchange({'jsonrpc': '2.0', 'id': 9, 'method': 'web3_clientVersion'}, token)
        assert missing['error']['code'] == -32601
        j['stages']['auth_and_rate'] = True
    j['passed'] = True
except BaseException as error:
    j['failure'] = repr(error)
    raise
finally:
    stop()
    j['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({'passed': j.get('passed', False), 'directory': str(out), 'mode': j['mode']}))
