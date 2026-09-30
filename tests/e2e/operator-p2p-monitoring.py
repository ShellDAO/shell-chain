#!/usr/bin/env python3
"""Real libp2p/RocksDB acceptance for peer, import and catch-up monitoring."""
import datetime
import json
import os
from pathlib import Path
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
    raise SystemExit('Build shell-node with --features libp2p first or set SHELL_NODE_BIN')
runtime = Path(tempfile.mkdtemp(prefix='shell-p2p-monitoring-'))
os.chmod(runtime, 0o700)
audit = runtime / 'results'
audit.mkdir()
result = {'start': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'runtime': str(runtime), 'binary_version': subprocess.check_output([str(binary), '--version'], text=True).strip(), 'commands': [], 'samples': [], 'assertions': {}, 'scope': 'Two isolated dev nodes, fresh validator key, one-second blocks and a 16-block backlog. No public network or load validation.'}
processes = {}
logs = {}
ports = {}
held = []
for name in ['validator', 'follower']:
    ports[name] = {}
    for kind in ['rpc', 'metrics', 'p2p']:
        s = socket.socket(); s.bind(('127.0.0.1', 0)); held.append(s)
        ports[name][kind] = s.getsockname()[1]
for s in held:
    s.close()
result['ports'] = ports

def save():
    (audit / 'runtime.json').write_text(json.dumps(result, indent=2) + '\n')

def cli(label, args):
    cmd = [str(binary), *map(str, args)]
    p = subprocess.run(cmd, cwd=runtime, capture_output=True, text=True, timeout=120)
    (audit / (label + '.log')).write_text(p.stdout + p.stderr)
    result['commands'].append({'label': label, 'command': cmd, 'exit_code': p.returncode})
    save()
    assert p.returncode == 0, (label, p.stderr)
    return p.stdout

def request(url, data=None):
    req = urllib.request.Request(url, data, {'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def rpc(name, method, params=None):
    _, body = request(f'http://127.0.0.1:{ports[name]["rpc"]}', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode())
    d = json.loads(body)
    if 'error' in d:
        raise RuntimeError(d['error'])
    return d['result']

def endpoint(name, path):
    return request(f'http://127.0.0.1:{ports[name]["metrics"]}{path}')

def until(fn, seconds=60):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        for name, proc in processes.items():
            if proc.poll() is not None:
                raise RuntimeError(f'{name} exited {proc.returncode}')
        try:
            v = fn()
            if v:
                return v
        except (OSError, ValueError) as e:
            last = str(e)
        time.sleep(0.05)
    raise TimeoutError(str(last))

def start(name, bootnode=None):
    cmd = [str(binary), 'run', '--datadir', str(runtime/name), '--network', 'dev', '--chain-id', '1337', '--db', 'rocksdb', '--rpc-addr', f'127.0.0.1:{ports[name]["rpc"]}', '--rpc-api', 'eth,net,web3,shell', '--metrics-addr', f'127.0.0.1:{ports[name]["metrics"]}', '--p2p', '--p2p-addr', f'127.0.0.1:{ports[name]["p2p"]}', '--block-time', '1000', '--max-idle-interval', '0', '--consensus-engine', 'wpoa', '--log-level', 'info']
    if name == 'validator':
        cmd += ['--keystore', str(runtime/'validator.json'), '--password-file', str(runtime/'password'), '--node-role', 'validator']
    else:
        cmd += ['--node-role', 'prover']
    if bootnode:
        cmd += ['--bootnode', bootnode]
    logs[name] = (audit/(name+'.log')).open('w')
    processes[name] = subprocess.Popen(cmd, stdout=logs[name], stderr=subprocess.STDOUT)
    result['commands'].append({'label': 'start-'+name, 'command': cmd, 'pid': processes[name].pid})
    save()

def sample(name):
    status, body = endpoint(name, '/health'); ready, rbody = endpoint(name, '/ready')
    _, after = endpoint(name, '/health')
    health = json.loads(body)
    after_health = json.loads(after)
    # Separate HTTP requests can straddle the end of synchronization.
    stable_sync = health.get('syncing') and after_health.get('syncing')
    _, exposition = endpoint(name, '/metrics')
    metrics = {}
    for line in exposition.splitlines():
        if line and not line.startswith('#') and '{' not in line and len(line.split()) == 2:
            k, v = line.split(); metrics[k] = float(v)
    return {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'node': name, 'health': health, 'stable_sync': bool(stable_sync), 'ready_status': ready, 'ready': json.loads(rbody), 'metrics': {k:v for k,v in metrics.items() if k in ['shell_block_height','shell_peer_count','shell_blocks_imported_total','shell_syncing','shell_production_ready']}}

try:
    pw = runtime/'password'; pw.write_text(secrets.token_hex(24)); os.chmod(pw, 0o600)
    cli('key', ['--password-file', pw, 'key', 'generate', '--algorithm', 'mldsa65', '--output', runtime/'validator.json'])
    key = json.loads((runtime/'validator.json').read_text())
    genesis = {'chain_id':1337,'chain_name':'p2p-monitoring-acceptance','network_type':'Dev','timestamp':int(time.time()),'gas_limit':30000000,'extra_data':'p2p-monitoring-acceptance','consensus':{'engine':'wpoa','authorities':[key['address']],'authority_pubkeys':['0x'+key['public_key'].removeprefix('0x')],'weights':[1],'block_time_secs':1,'max_future_secs':60,'epoch_length':0},'alloc':{key['address']:{'balance':'0x3635c9adc5dea00000'}},'boot_nodes':[]}
    gen = runtime/'genesis.json'; gen.write_text(json.dumps(genesis))
    for name in ports:
        cli('init-'+name, ['init','--datadir',runtime/name,'--genesis',gen,'--network','dev','--chain-id','1337'])
    start('validator')
    until(lambda: int(rpc('validator','eth_blockNumber'),16) >= 16)
    log = (audit/'validator.log').read_text()
    bootnode = re.findall(r'/ip4/127\.0\.0\.1/tcp/\d+/p2p/[A-Za-z0-9]+',log)[-1]
    result['bootnode'] = bootnode
    start('follower',bootnode)
    until(lambda: rpc('follower','eth_chainId') == '0x539')
    end = time.monotonic()+35
    last = None
    while time.monotonic()<end:
        s = sample('follower')
        signature = (s['health']['block_height'], s['ready_status'], s['health'].get('syncing'), s['stable_sync'], s['metrics'].get('shell_peer_count'))
        if signature != last:
            result['samples'].append(s); last = signature; save()
        time.sleep(0.025)
    final = {n:sample(n) for n in ports}; result['final'] = final
    common = min(s['health']['block_height'] for s in final.values())
    blocks = {n:rpc(n,'eth_getBlockByNumber',[hex(common),False]) for n in ports}
    result['common_height'] = common
    result['common_hashes'] = {n:b['hash'] for n,b in blocks.items()}
    f = final['follower']; v = final['validator']; samples = result['samples']
    result['assertions'] = {
        'same_chain': blocks['validator']['hash'] == blocks['follower']['hash'] and common >=16,
        'follower_imports_counted': f['metrics']['shell_blocks_imported_total'] >=16,
        'follower_metrics_height_matches_health': f['metrics']['shell_block_height'] == f['health']['block_height'],
        'peers_observed': f['metrics']['shell_peer_count'] >=1 and v['metrics']['shell_peer_count'] >=1,
        'ready_after_catchup': f['ready_status']==200 and not f['health']['syncing'],
        'syncing_observed': any(s['health']['syncing'] for s in samples),
        'not_ready_while_syncing': any(s['stable_sync'] for s in samples) and all(s['ready_status']==503 for s in samples if s['stable_sync']),
    }
    result['passed'] = all(result['assertions'].values())
    print(json.dumps(result['assertions']),flush=True)
except BaseException as e:
    result['error'] = repr(e)
    raise
finally:
    for proc in processes.values():
        if proc.poll() is None: proc.terminate()
    for proc in processes.values():
        try: proc.wait(timeout=20)
        except subprocess.TimeoutExpired: proc.kill();proc.wait()
    for log in logs.values():log.close()
    result['nodes_stopped'] = all(p.poll() is not None for p in processes.values())
    result['end'] = datetime.datetime.now(datetime.timezone.utc).isoformat(); save()
    print('Results and isolated node data:',runtime,flush=True)
if not result.get('passed'):
    raise SystemExit('P2P monitoring assertions failed; see runtime.json. Unobserved sync remains unverified.')
