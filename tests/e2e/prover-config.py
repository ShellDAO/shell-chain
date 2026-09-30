#!/usr/bin/env python3
"""Verify configured STARK input creation and RocksDB restart through the real CLI.

Build shell-node first, or set SHELL_NODE_BIN. Uses Python 3 standard library,
isolated dev nodes and fresh test keys. Retains private data and JSON receipts
in a temporary directory. One transaction remains below the 512-entry proving
threshold: a stored input commitment is not a completed proof.
Use --prover-key to isolate key selection, restart identity and non-production;
this mode does not verify prover registration or completed proofs.
"""
from pathlib import Path
import argparse, datetime, json, os, re, secrets, socket, subprocess, tempfile, time, urllib.request
repo = Path(__file__).resolve().parents[2]
binary = Path(os.environ.get('SHELL_NODE_BIN', str(repo / 'target/debug/shell-node'))).resolve()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prover-key', action='store_true', help='check standalone prover keystore selection and restart')
options = parser.parse_args()
mode = 'prover-key' if options.prover_key else 'runtime'
out = Path(tempfile.mkdtemp(prefix='shell-prover-config-'))
os.chmod(out, 0o700)
audit = out / 'results'
audit.mkdir()
result = {'mode': mode, 'out': str(out), 'commands': [], 'cases': [], 'start': datetime.datetime.now(datetime.timezone.utc).isoformat()}

def save():
    (audit / (mode + '.json')).write_text(json.dumps(result, indent=2) + '\n')

def run(label, args):
    cmd = [str(binary), *map(str, args)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    (audit / (mode + '-' + label + '.log')).write_text(r.stdout + r.stderr)
    result['commands'].append({'command': cmd, 'exit_code': r.returncode, 'log': mode + '-' + label + '.log'})
    save()
    assert r.returncode == 0, (label, r.stderr)
    return r.stdout
pw = out / 'password'
pw.write_text(secrets.token_hex(24))
os.chmod(pw, 0o600)
key = out / 'key.json'
run('key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'dilithium3', '--output', key])
address = re.search('Address:\\s*(0x[0-9a-f]+)', run('inspect', ['key', 'inspect', key])).group(1)
genesis = out / 'genesis.json'
genesis.write_text(json.dumps({'chain_id': 1337, 'chain_name': 'prover-config', 'network_type': 'Dev', 'timestamp': int(time.time()), 'gas_limit': 30000000, 'extra_data': 'prover-config', 'consensus': {'engine': 'poa', 'authorities': [address], 'block_time_secs': 2, 'epoch_length': 0}, 'alloc': {address: {'balance': '0x3635c9adc5dea00000'}}, 'boot_nodes': []}))
if options.prover_key:
    isolated_genesis = json.loads(genesis.read_text())
    isolated_genesis['consensus']['authorities'] = ['0x' + '42' * 32]
    genesis.write_text(json.dumps(isolated_genesis))
    # Same generated key and genesis for both variants: only the documented
    # keystore line changes. Never register this key as a block producer.
    for configured in [False, True]:
        label = 'configured-key' if configured else 'omitted-key-baseline'
        data = out / label
        config = out / (label + '.toml')
        config.write_text('[node]\nnode_role = "prover"\n' +
                          (f'keystore = {json.dumps(str(key))}\n' if configured else '') +
                          '[metrics]\nenabled = false\n')
        run(label + '-init', ['--datadir', data, 'init', '--genesis', genesis, '--chain-id', '1337', '--network', 'dev'])
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cmd = [str(binary), '--password-file', str(pw), 'run', '--config', str(config),
               '--datadir', str(data), '--network', 'dev', '--db', 'rocksdb',
               '--rpc-addr', f'127.0.0.1:{port}', '--block-time', '100', '--max-idle-interval', '0']
        c = {'label': label, 'command': cmd, 'generated_address': address, 'starts': []}
        result['cases'].append(c)
        for restart in [False, True]:
            logpath = audit / (label + ('-restart' if restart else '') + '.log')
            with logpath.open('w') as log:
                proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                        env={**os.environ, 'RUST_LOG': 'info'})
                try:
                    for _ in range(150):
                        assert proc.poll() is None, logpath.read_text()
                        try:
                            req = urllib.request.Request(f'http://127.0.0.1:{port}',
                                b'{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}',
                                {'Content-Type': 'application/json'})
                            with urllib.request.urlopen(req, timeout=2) as response:
                                height = json.load(response)['result']
                            if 'Background prover service started' not in logpath.read_text():
                                time.sleep(0.1)
                                continue
                            break
                        except OSError:
                            time.sleep(0.1)
                    else:
                        raise RuntimeError('prover startup timeout')
                    text = logpath.read_text()
                    authority = re.search(r'Node authority: (0x[0-9a-f]{64})', text).group(1)
                    assert (authority == address) == configured, (authority, address)
                    assert ('No keystore provided' in text) == (not configured)
                    # The prover remains a non-producing role despite loading a key.
                    time.sleep(2.5)
                    with urllib.request.urlopen(req, timeout=2) as response:
                        after = json.load(response)['result']
                    assert height == after == '0x0', (height, after)
                    c['starts'].append({'restart': restart, 'authority': authority,
                                        'height': after, 'log': str(logpath), 'passed': True})
                    if restart:
                        assert c['starts'][0]['authority'] == authority
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    c['node_stopped'] = True
                    save()
    result['passed'] = True
    result['end'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(json.dumps(result))
    raise SystemExit(0)

cases = [('configured-enabled', True, [], True)]
cases += [('explicit-disabled', True, ['--enable-stark-aggregation=false'], False), ('explicit-enabled', False, ['--enable-stark-aggregation'], True), ('configured-disabled', False, [], False), ('default', None, [], False)]
for label, enabled, flags, expected in cases:
    data = out / label
    config = out / (label + '.toml')
    config.write_text('[node]\nnode_role = "validator-prover"\n[metrics]\nenabled = false\n' + ('' if enabled is None else '[consensus]\nenable_stark_aggregation = ' + str(enabled).lower() + '\n'))
    run(label + '-init', ['--datadir', data, 'init', '--genesis', genesis, '--chain-id', '1337', '--network', 'dev'])
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    url = f'http://127.0.0.1:{port}'

    def rpc(m, params=None):
        req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': params or []}).encode(), {'Content-Type': 'application/json'})
        d = json.load(urllib.request.urlopen(req, timeout=3))
        assert 'error' not in d, d
        return d['result']
    cmd = [str(binary), '--password-file', str(pw), 'run', '--config', str(config), '--datadir', str(data), '--keystore', str(key), '--network', 'dev', '--db', 'rocksdb', '--rpc-addr', f'127.0.0.1:{port}', '--block-time', '1000', '--max-idle-interval', '0', *flags]
    c = {'label': label, 'command': cmd, 'expected_commitment': expected}
    result['cases'].append(c)
    save()
    for restart in [False, True]:
        log = (audit / (mode + '-' + label + ('-restart' if restart else '') + '.log')).open('w')
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        c['pid'] = proc.pid
        try:
            for _ in range(100):
                assert proc.poll() is None, 'node exited'
                try:
                    rpc('eth_blockNumber')
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('startup timeout')
            if not restart:
                txout = run(label + '-send', ['--password-file', pw, 'tx', 'send', '--keystore', key, '--to', '0x' + 'ab' * 32, '--value', '1', '--rpc-url', url])
                txhash = re.search('0x[0-9a-f]{64}', txout).group(0)
                for _ in range(100):
                    receipt = rpc('eth_getTransactionReceipt', [txhash])
                    if receipt:
                        break
                    time.sleep(0.1)
                assert receipt and receipt['status'] == '0x1', receipt
                block = rpc('eth_getBlockByHash', [receipt['blockHash'], True])
                c.update(receipt=receipt, block=block)
                present = block.get('sigAggregateProofSize', 0) > 0
                c['passed'] = present == expected
                c['proof_amendment'] = rpc('shell_getProofAmendment', [receipt['blockHash']])
                assert c['proof_amendment'] is None, 'one transaction must not bypass512-entry proof threshold'
                assert c['passed'], f'{label}: expected commitment={expected}, actual={present}'
            else:
                after = rpc('eth_getBlockByHash', [c['receipt']['blockHash'], True])
                c['persisted'] = after == c['block']
                assert c['persisted']
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.close()
            c['node_stopped'] = True
            save()
result['passed'] = all((c.get('passed') and c.get('persisted') for c in result['cases']))
result['end'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
save()
print(json.dumps(result))
