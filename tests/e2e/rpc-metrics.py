#!/usr/bin/env python3
"""Verify live RPC metrics on an isolated dev node and physical RocksDB reopen.

Build shell-node first or set SHELL_NODE_BIN. Python 3 standard library only.
Uses fresh data, loopback ports and a generated local test API token. Retains
private test data, metrics snapshots and execution receipts in a temp directory.
"""
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

repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', repo / 'target/debug/shell-node')).resolve()
out = Path(tempfile.mkdtemp(prefix='shell-rpc-metrics-'))
out.chmod(0o700)
result = {'directory': str(out), 'processes': [], 'requests': [], 'stages': {},
          'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
process = None
row = None


def save():
    (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


rpc_port, metrics_port = free_port(), free_port()


def scrape(label):
    with urllib.request.urlopen(f'http://127.0.0.1:{metrics_port}/metrics', timeout=3) as response:
        text = response.read().decode()
    (out / (label + '.prom')).write_text(text)
    return text


def sample(text, name, **labels):
    for line in text.splitlines():
        if line.startswith('#'):
            continue
        match = re.fullmatch(r'([^ {]+)(?:\{(.*)\})? ([^ ]+)(?: .*)?', line)
        if not match or match[1] != name:
            continue
        actual = dict(re.findall(r'(\w+)="([^"]*)"', match[2] or ''))
        if actual == labels:
            return float(match[3])
    return 0.0


def call(method=None, params=None, token=None, body=None, notification=False):
    if body is None:
        value = {'jsonrpc': '2.0', 'method': method, 'params': params or []}
        if not notification:
            value['id'] = len(result['requests']) + 1
        body = json.dumps(value)
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(f'http://127.0.0.1:{rpc_port}', body.encode(), headers)
    try:
        response = urllib.request.urlopen(request, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, raw = response.status, response.read().decode()
    try:
        value = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        value = raw
    result['requests'].append({'body': body, 'authenticated': token is not None,
                               'http_status': status, 'response': value})
    save()
    return status, value


def stop():
    global process
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    row['exit_code'] = process.returncode
    row['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    process = None
    save()
    assert row['exit_code'] == 0, row


def start(token=None):
    global process, row
    args = ['run', '--datadir', str(out / 'data'), '--network', 'dev', '--chain-id', '1337',
            '--db', 'rocksdb', '--rpc-addr', f'127.0.0.1:{rpc_port}',
            '--metrics-addr', f'127.0.0.1:{metrics_port}', '--max-idle-interval', '1209600000']
    if token:
        args += ['--rpc-api-key', token, '--rpc-rate-limit', '2']
    log = out / f'node-{len(result["processes"])}.log'
    with log.open('w') as stream:
        process = subprocess.Popen([str(binary), *args], stdout=stream, stderr=subprocess.STDOUT)
    recorded = list(args)
    if token:
        recorded[recorded.index('--rpc-api-key') + 1] = '<generated token in rpc-token>'
    row = {'pid': process.pid, 'args': recorded, 'log': str(log),
           'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    result['processes'].append(row)
    save()
    for _ in range(150):
        assert process.poll() is None, log
        try:
            return scrape('start-' + str(len(result['processes'])))
        except OSError:
            time.sleep(0.1)
    raise AssertionError('Metrics listener did not start')


try:
    initial = start()
    assert sample(initial, 'shell_rpc_requests_total', method='eth_chainId', status='200') == 0
    for _ in range(3):
        status, value = call('eth_chainId')
        assert status == 200 and value['result'] == '0x539'
    measured = scrape('three-calls')
    assert sample(measured, 'shell_rpc_requests_total', method='eth_chainId', status='200') == 3
    assert sample(measured, 'shell_rpc_duration_seconds_count', method='eth_chainId') == 3
    assert sample(measured, 'shell_rpc_request_duration_seconds_count', method='eth_chainId') == 3
    assert sample(measured, 'shell_rpc_duration_seconds_sum', method='eth_chainId') >= 0
    for index in range(2):
        status, value = call(f'unregistered-method-{index}')
        assert status == 200 and value['error']['code'] == -32601
    status, value = call('eth_getBalance')
    assert status == 200 and value['error']['code'] == -32602
    status, value = call(body=json.dumps([
        {'jsonrpc': '2.0', 'id': 101, 'method': 'eth_chainId', 'params': []},
        {'jsonrpc': '2.0', 'id': 102, 'method': 'eth_chainId', 'params': []},
    ]))
    assert status == 200 and all(reply['result'] == '0x539' for reply in value)
    notification_status, _ = call('eth_chainId', notification=True)
    assert 200 <= notification_status < 300
    measured = scrape('errors-batch-notification')
    assert sample(measured, 'shell_rpc_requests_total', method='__unknown__', status='200') == 2
    assert sample(measured, 'shell_rpc_duration_seconds_count', method='eth_getBalance') == 1
    # Every exchange is observed once. A transport acknowledgement must not
    # invent handler work; a server that dispatches notifications may time it.
    handled = sample(measured, 'shell_rpc_duration_seconds_count', method='eth_chainId')
    transport = sample(measured, 'shell_rpc_duration_seconds_count', method='__transport__')
    assert handled >= 5 and handled + transport == 6
    requests = sample(measured, 'shell_rpc_requests_total', method='eth_chainId', status='200')
    if notification_status != 200:
        requests += sample(measured, 'shell_rpc_requests_total', method='eth_chainId', status=str(notification_status))
    assert requests + sample(measured, 'shell_rpc_requests_total', method='__transport__', status=str(notification_status)) == 6
    assert 'unregistered-method-' not in measured
    stable = scrape('scrape-does-not-count')
    assert [line for line in stable.splitlines() if line.startswith('shell_rpc_')] == [
        line for line in measured.splitlines() if line.startswith('shell_rpc_')]
    status, value = call('eth_getBlockByNumber', ['latest', False])
    assert status == 200
    head = value['result']
    result['stages']['live'] = {'head': head, 'notification_status': notification_status}
    stop()
    token = secrets.token_hex(24)
    token_file = out / 'rpc-token'
    token_file.write_text(token)
    token_file.chmod(0o600)
    initial = start(token)
    assert sample(initial, 'shell_rpc_requests_total', method='eth_chainId', status='200') == 0
    status, _ = call('eth_chainId')
    assert status == 401
    status, value = call('eth_getBlockByNumber', ['latest', False], token)
    assert status == 200 and value['result'] == head
    status, value = call('eth_chainId', token=token)
    assert status == 200 and value['result'] == '0x539'
    status, _ = call('eth_chainId', token=token)
    assert status == 429
    measured = scrape('auth-rate-limit-reopen')
    assert sample(measured, 'shell_rpc_requests_total', method='__transport__', status='401') == 1
    assert sample(measured, 'shell_rpc_requests_total', method='__transport__', status='429') == 1
    assert sample(measured, 'shell_rpc_requests_total', method='eth_chainId', status='200') == 1
    assert sample(measured, 'shell_rpc_duration_seconds_count', method='__transport__') == 2
    result['stages']['reopen'] = {'same_head': True, 'counters_reset': True,
                                  'unauthorized_status': 401, 'limited_status': 429}
    result['passed'] = True
except BaseException as error:
    result['failure'] = repr(error)
    raise
finally:
    stop()
    result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps({'passed': result.get('passed', False), 'directory': str(out)}))
