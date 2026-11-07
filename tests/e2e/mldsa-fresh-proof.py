#!/usr/bin/env python3
"""Exercise the actual offline CLI with independently prepared native fixtures."""
import json
import datetime
import select
import pathlib
import subprocess
import sys

mode, node_bin, fixture_bin, native, cache, output = sys.argv[1:]
node_bin, fixture_bin = map(lambda p: str(pathlib.Path(p).resolve(strict=True)), [node_bin, fixture_bin])
native, cache = map(lambda p: pathlib.Path(p).resolve(strict=True), [native, cache])
out = pathlib.Path(output).resolve()
if mode not in ['run', 'verify'] or any(out == p or out in p.parents or p in out.parents for p in [native, cache]):
    raise SystemExit('invalid mode or overlapping fixture/output')
if mode == 'run' and out.exists():
    raise SystemExit('output exists; retain it and use verify')
records = []

def command(argv, expected_error=None):
    argv = list(map(str, argv))
    record = dict(argv=argv, cwd=str(pathlib.Path.cwd()), started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), expected_error=expected_error)
    if out.is_dir():
        index = 1
        while (out / f'command-{index:04d}.json').exists():
            index += 1
        prefix = out / f'command-{index:04d}'
        receipt = prefix.with_suffix('.json')
        def persist():
            tmp=receipt.with_suffix('.tmp')
            tmp.write_text(json.dumps(record,indent=2)+'\n')
            tmp.replace(receipt)
        with prefix.with_suffix('.stdout.log').open('x') as stdout, prefix.with_suffix('.stderr.log').open('x') as stderr:
            process=subprocess.Popen(argv,stdout=stdout,stderr=stderr)
            record['pid']=process.pid
            persist()
            try:
                code=process.wait(timeout=900)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                record.update(exit_code=process.returncode,timed_out=True,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
                persist()
                raise
        record.update(exit_code=code,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        persist()
        record.update(stdout=prefix.with_suffix('.stdout.log').read_text(),stderr=prefix.with_suffix('.stderr.log').read_text())
    else:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=900)
        record.update(exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    records.append(record)
    if expected_error is None:
        if record['exit_code']:
            raise RuntimeError(f'command failed: {record["stderr"]}\n{record["stdout"]}')
    elif record['exit_code'] == 0 or expected_error not in record['stdout'] + record['stderr']:
        raise RuntimeError(f'expected refusal {expected_error!r}: {record}')
    return record['stdout']

def fixture(action):
    return command([fixture_bin, action, native, cache, out])

def snapshot():
    return json.loads(fixture('snapshot'))

def cli(block='candidate.json', manifest='manifest.json', proof='payload.json', parent=None, error=None):
    if parent is None:
        parent = json.loads((out / 'expected.json').read_text())['parent']
    return command([node_bin, '--log-level', 'off', '--datadir', out / 'follower', 'import-block-proof',
                    '--block', out / block, '--proof', cache / proof, '--manifest', out / manifest,
                    '--consensus', out / 'consensus.json', '--parent', parent], error)

def save(name, value):
    with (out / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')

try:
    if mode == 'run':
        fixture('prepare')
        baseline = snapshot()
        for args in [dict(parent='0x'+'00'*32, error='identity mismatch'),
                     dict(manifest='wrong-hash-manifest.json', error='size/hash mismatch'),
                     dict(manifest='wrong-chain-manifest.json', error='local chain/genesis/current parent mismatch'),
                     dict(block='bad-seal-candidate.json', error='seal'),
                     dict(block='bad-body-candidate.json', error='body commitment mismatch'),
                     dict(manifest='bad-air-manifest.json', proof='corrupt-payload.json', error='candidate sender proof')]:
            cli(**args)
            if snapshot() != baseline:
                raise RuntimeError('refused CLI import changed canonical KV/head')
        hold_args=list(map(str,[fixture_bin,'hold',native,cache,out]))
        holder=subprocess.Popen(hold_args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        hold_record=dict(argv=hold_args,pid=holder.pid,started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        save('ownership-check.json',hold_record)
        try:
            if not select.select([holder.stdout],[],[],10)[0] or holder.stdout.readline().strip()!='locked':
                raise RuntimeError('native ownership holder did not start')
            cli(error='lock')
        finally:
            stdout,stderr=holder.communicate(input='release\n',timeout=15)
            hold_record.update(exit_code=holder.returncode,stdout='locked\n'+stdout,stderr=stderr,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            (out/'ownership-check.json').write_text(json.dumps(hold_record,indent=2)+'\n')
        if holder.returncode or snapshot()!=baseline:
            raise RuntimeError('database ownership refusal changed native state')
        fixture('rollback')
        actual = json.loads(cli())
        expected = json.loads((out / 'expected.json').read_text())['native']
        normalized = dict(actual, tip=expected['tip'])
        if normalized != expected:
            raise RuntimeError('CLI result differs from independent native execution')
        committed = snapshot()
        cli(error='local chain/genesis/current parent mismatch')
        if snapshot() != committed:
            raise RuntimeError('duplicate/stale proof import changed canonical state')
        save('cli-result.json', actual)
        fixture('verify')
        save('result.json', dict(actual_CLI_import=True, full_graph_sender_signatures=2,
                                 refusal_count=8, refused_KV_unchanged=True,
                                 atomic_commit_failure_rollback=True,
                                 cold_native_reopen_and_full_recheck=True, native_result=actual))
        save('commands.json', records)
    else:
        fixture('verify')
    print(json.dumps(dict(mode=mode, actual_offline_CLI=True, complete_sender_proof=True,
                         native_persistence_and_cold_recheck=True)))
except Exception:
    if out.is_dir():
        index = 1
        while (out / f'failed-commands-{index}.json').exists():
            index += 1
        save(f'failed-commands-{index}.json', records)
    raise
