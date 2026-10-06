#!/usr/bin/env python3
"""Real CLI default4096 retention and independent libp2p archive recovery."""
import argparse, datetime, hashlib, json, socket, subprocess, tempfile, time, urllib.request, os, re
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--output-dir', type=Path, required=True, help='new directory for JSON results and node logs')
args = p.parse_args()
if not __debug__:
    p.error("run without Python optimization; assertions are required")
binary = args.binary.resolve(strict=True)
out = args.output_dir.resolve()
out.mkdir(parents=True, exist_ok=False)
result = {'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source_substitution': True, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'scope': 'one validator and independent archive observer; 1s blocks; default4096 bodies; no finality injection', 'commands': [], 'samples': []}

def save():
    q = out / 'retention-cli-runtime.tmp'
    q.write_text(json.dumps(result, indent=2))
    q.replace(out / 'retention-cli-runtime.json')

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def rpc(rp, method, params=[]):
    req = urllib.request.Request(f'http://127.0.0.1:{rp}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as f:
        v = json.load(f)
    if 'error' in v:
        raise RuntimeError(v['error'])
    return v['result']
processes = {}
logs = []
peer_ids = {}

def stop(name):
    proc = processes.pop(name, None)
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        result.setdefault('exits', []).append([name, proc.returncode])
        save()

def wait(fn, seconds=90):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        for name, proc in processes.items():
            if proc.poll() is not None:
                raise RuntimeError(f'{name} exited {proc.returncode}')
        try:
            v = fn()
            if v:
                return v
        except (OSError, RuntimeError) as e:
            last = str(e)
        time.sleep(0.5)
    raise RuntimeError(f'timed out: {last}')
try:
    with tempfile.TemporaryDirectory(prefix='shell-retention-cli-') as directory:
        local = Path(directory)
        pw = local / 'password'
        pw.write_text('isolated-retention\n')
        pw.chmod(0o600)

        def cli(*cmd):
            c = subprocess.run([str(binary), '--password-file', str(pw), *map(str, cmd)], capture_output=True, text=True, timeout=30)
            if c.returncode:
                raise RuntimeError(c.stderr)
            return c.stdout.strip()
        for name in ('validator', 'observer', 'sender'):
            cli('key', 'generate', '--algorithm', 'mldsa65', '--output', local / name)
        validator = json.loads((local / 'validator').read_text())
        sender = json.loads((local / 'sender').read_text())['address']
        recipient = '0x' + '42' * 32
        initial = 10 ** 24
        value = 12345
        genesis = {'chain_id': 31337, 'chain_name': 'isolated-retention', 'network_type': 'Dev', 'timestamp': int(time.time()) - 2, 'gas_limit': 30000000, 'extra_data': 'retention-cli', 'consensus': {'engine': 'wpoa', 'authorities': [validator['address']], 'authority_pubkeys': [validator['public_key']], 'block_time_secs': 1, 'max_future_secs': 60, 'epoch_length': 0}, 'alloc': {sender: {'balance': hex(initial), 'nonce': 0}}, 'boot_nodes': []}
        for name in ('light', 'archive'):
            (local / name).mkdir()
            (local / name / 'genesis.json').write_text(json.dumps(genesis))
        ports = {name: {key: port() for key in ('rpc', 'p2p', 'metrics')} for name in ('light', 'archive')}

        def start(name, profile, key, peer=None):
            ps = ports[name]
            cmd = [str(binary), '--password-file', str(pw), 'run', '--storage-profile', profile, '--datadir', str(local / name), '--keystore', str(local / key), '--db', 'rocksdb', '--rpc-addr', f"127.0.0.1:{ps['rpc']}", '--rpc-api', 'eth,net,web3,shell', '--metrics-addr', f"127.0.0.1:{ps['metrics']}", '--chain-id', '31337', '--block-time', '1000', '--max-idle-interval', '1', '--consensus-engine', 'wpoa', '--node-role', 'validator', '--p2p', '--p2p-addr', f"127.0.0.1:{ps['p2p']}"]
            if peer:
                cmd += ['--bootnode', f"/ip4/127.0.0.1/tcp/{ports[peer]['p2p']}/p2p/{peer_ids[peer]}"]
            result['commands'].append(cmd)
            log = (out / f"retention-cli-{name}-{len(result['commands'])}.log").open('w')
            logs.append(log)
            processes[name] = subprocess.Popen(cmd, stdout=log, stderr=log, env={**os.environ, 'RUST_LOG': 'warn,shell_network=info'})
            save()
            wait(lambda: rpc(ps['rpc'], 'eth_chainId') == '0x7a69')

            def identity():
                matches = re.findall('/p2p/([A-Za-z0-9]+)', Path(log.name).read_text())
                return matches[-1] if matches else None
            peer_ids[name] = wait(identity)
        try:
            start('light', 'light', 'validator')
            start('archive', 'archive', 'observer', 'light')
            lr = ports['light']['rpc']
            ar = ports['archive']['rpc']
            result['profiles'] = [rpc(x, 'shell_getStorageProfile') for x in (lr, ar)]
            assert result['profiles'][0]['body_retention'] == 4096
            wait(lambda: int(rpc(ar, 'eth_blockNumber'), 16) >= 2)
            tx = cli('tx', 'send', '--to', recipient, '--value', value, '--gas-limit', '100000', '--keystore', local / 'sender', '--rpc-url', f'http://127.0.0.1:{lr}')
            receipt = wait(lambda: rpc(lr, 'eth_getTransactionReceipt', [tx]))
            assert int(receipt['status'], 16) == 1
            result['receipt'] = receipt
            target = int(receipt['blockNumber'], 16)
            original = rpc(lr, 'shell_getBlockByNumber', [hex(target), 'full'])
            result['original'] = original
            wait(lambda: rpc(ar, 'shell_getBlockByNumber', [hex(target), 'full']) == original)
            goal = target + 4096 + 2
            result['goal_finalized'] = goal
            save()
            deadline = time.monotonic() + 5400
            while True:
                info = rpc(lr, 'shell_getFinalityInfo')
                af = rpc(ar, 'shell_getFinalityInfo')
                result['samples'].append({'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'light': info, 'archive': af})
                save()
                if int(info['lastFinalizedBlock'], 16) >= goal and int(af['lastFinalizedBlock'], 16) >= goal:
                    break
                assert time.monotonic() < deadline, 'default4096 finality deadline exceeded'
                for name, proc in processes.items():
                    assert proc.poll() is None, (name, proc.returncode)
                time.sleep(30)
            result['pruned_body'] = rpc(lr, 'shell_getBlockByNumber', [hex(target), 'full'])
            assert result['pruned_body'] is None, 'old body still retained'
            assert rpc(ar, 'shell_getBlockByNumber', [hex(target), 'full']) == original
            stop('light')
            start('light', 'full', 'validator', 'archive')
            wait(lambda: rpc(lr, 'shell_getBlockByNumber', [hex(target), 'full']) == original, 180)
            result['backfilled'] = True

            def accounts():
                return [int(rpc(lr, 'eth_getBalance', [sender, 'latest']), 16), int(rpc(lr, 'eth_getTransactionCount', [sender, 'latest']), 16), int(rpc(lr, 'eth_getBalance', [recipient, 'latest']), 16)]
            assert accounts() == [initial - value, 1, value]
            result['accounts'] = accounts()
            stop('light')
            start('light', 'full', 'validator', 'archive')
            assert rpc(lr, 'shell_getBlockByNumber', [hex(target), 'full']) == original
            assert accounts() == result['accounts']
            result['accepted'] = True
            save()
        finally:
            for name in list(processes):
                stop(name)
except Exception as e:
    result['error'] = repr(e)
    raise
finally:
    for name in list(processes):
        stop(name)
    for log in logs:
        log.close()
    result['ended'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
