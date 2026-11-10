"""Full large native envelope membership with unchanged small transaction ID."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys


def main():
    binary, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if out.exists():
        raise RuntimeError("original large-body output already exists")
    out.mkdir()
    commands = out / "commands"
    commands.mkdir()

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run(label, args, expected=0):
        args = [str(x) for x in args]
        log = commands / (label + ".log")
        receipt = {"cwd": str(Path.cwd()), "argv": args, "log": str(log),
                   "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "expected_exit_code": expected}
        with log.open("x") as stream:
            process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT)
            receipt["pid"] = process.pid
            (commands / (label + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
            receipt["exit_code"] = process.wait()
        receipt["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (commands / (label + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
        if process.returncode != expected:
            raise RuntimeError(f"{label}: expected {expected}, got {process.returncode}; see {log}")
        return json.loads(log.read_text().splitlines()[-1]) if expected == 0 else None

    inp = out / "input.json"
    if len(sys.argv) in [4, 5]:
        original = Path(sys.argv[3]).resolve()
        originals = {str(original): sha(original)}
        run("export-original", [binary, "export", original, "0", inp])
        source = "exact retained original Native block, no signing"
    elif len(sys.argv) == 3:
        originals = {}
        run("sample", [binary, "sample", inp])
        source = "separate genuine memory-only signature/body fixture; not Native execution"
    else:
        raise RuntimeError("usage: binary output [original-native-block.json [retained-proof-directory]]")
    native = run("native-reference", [binary, "inspect", inp])
    assert native["native_reference_only"] and not native["AIR_verified"]
    assert 16_384 < native["leaf_bytes"] <= 65_536
    assert native["identity_bytes"] == 80 and native["signing_bytes"] <= 4096
    proofdir = out / "proof"
    reused_cache = len(sys.argv) == 5
    cache_artifacts = {}
    if reused_cache:
        cache = Path(sys.argv[4]).resolve()
        if (cache / "inputs.json").read_bytes() != inp.read_bytes():
            raise RuntimeError("retained cache public inputs differ; refusing substitution")
        cache_artifacts = {str(p.relative_to(cache)): sha(p) for p in cache.rglob("*") if p.is_file()}
        shutil.copytree(cache, proofdir)
        first = run("reuse-original-proof", [binary, "resume", inp, proofdir])
        assert first["generated_steps"] == 0
    else:
        first = run("prove", [binary, "prove", inp, proofdir])
    assert first["body_membership_verified"] and not first["canonical_admission"]
    assert not first["signature_verified"] and first["body_hash_profile"] == 3 and first["membership_profile"] == 2
    assert bytes(first["transaction_id"]) == bytes.fromhex(native["transaction_id"][2:])
    assert bytes(first["signing_hash"]) == bytes.fromhex(native["signing_hash"][2:])
    assert bytes(first["body_root"]) == bytes.fromhex(native["body_root"][2:])
    assert first["leaf_bytes"] == native["leaf_bytes"]
    count = (native["leaf_bytes"] + 63) // 64 + (native["leaf_bytes"] + 1023) // 1024 - 1
    assert first["leaf_compressions"] == count
    assert first["recovered_steps"] > 0 if reused_cache else first["recovered_steps"] == 0
    frozen = {str(p.relative_to(proofdir)): sha(p) for p in proofdir.rglob("*") if p.is_file()}
    cold = run("cold-verify", [binary, "verify", inp, proofdir])
    assert cold["body_root"] == first["body_root"] and cold["transaction_id"] == first["transaction_id"]
    resumed = run("resume", [binary, "resume", inp, proofdir])
    assert resumed["generated_steps"] == 0 and resumed["recovered_steps"] > 0
    refused = run("mathematical-refusals", [binary, "refusals", inp, proofdir])
    assert len(refused["refusals"]) >= 19 and all(x["error"] for x in refused["refusals"])
    run("overwrite-refused", [binary, "prove", inp, proofdir], 1)
    wrong = json.loads(inp.read_text())
    # Native SignedTransaction JSON flattens sig_type and the raw hex signature.
    # Mutate bytes through that public representation, preserving every other field.
    transaction = wrong["block"]["transactions"][0]
    signature = transaction["signature"]
    if isinstance(signature, str):
        raw = bytearray.fromhex(signature.removeprefix("0x"))
        raw[-1] ^= 1
        transaction["signature"] = "0x" + raw.hex()
    else:
        data = signature["data"]
        if isinstance(data, str):
            raw = bytearray.fromhex(data.removeprefix("0x"))
            raw[-1] ^= 1
            signature["data"] = "0x" + raw.hex()
        else:
            data[-1] ^= 1
    changed = out / "wrong-witness.json"
    changed.write_text(json.dumps(wrong) + "\n")
    witness = run("changed-witness-native-reference", [binary, "inspect", changed])
    assert witness["transaction_id"] == native["transaction_id"] and witness["signing_hash"] == native["signing_hash"]
    assert witness["leaf_hash"] != native["leaf_hash"]
    run("same-ID-changed-witness-refused", [binary, "verify", changed, proofdir], 1)
    run("resume-replacement-refused", [binary, "resume", changed, proofdir], 1)
    for label, data in [("trailing", (proofdir / "envelope.cbor").read_bytes() + b"\0"),
                        ("corrupt", b"invalid certificate")]:
        target = out / label
        target.mkdir()
        (target / "envelope.cbor").write_bytes(data)
        run(label + "-refused", [binary, "verify", inp, target], 1)
    leaf_names = sorted(p.name for p in proofdir.glob("leaf-*.cbor"))
    assert len(leaf_names) == count
    partial = out / "partial-recovery"
    shutil.copytree(proofdir, partial, ignore=lambda directory, names:
                    [n for n in names if n in ["envelope.cbor", "hash-000.cbor", leaf_names[-1]]])
    retained = {str(p.relative_to(partial)): sha(p) for p in partial.rglob("*") if p.is_file()}
    recovered = run("partial-resume", [binary, "resume", inp, partial])
    assert recovered["generated_steps"] == 1 and recovered["leaf_compressions"] == count
    partial_cold = run("partial-cold-verify", [binary, "verify", inp, partial])
    assert partial_cold["transaction_id"] == first["transaction_id"] and partial_cold["body_root"] == first["body_root"]
    assert sha(partial / "envelope.cbor") == sha(proofdir / "envelope.cbor")
    assert all(sha(partial / n) == h for n, h in retained.items())
    assert all(sha(proofdir / n) == h for n, h in frozen.items())
    assert all(sha(Path(n)) == h for n, h in originals.items())
    if reused_cache:
        assert all(sha(cache / n) == h for n, h in cache_artifacts.items())
        assert all(sha(proofdir / n) == h for n, h in cache_artifacts.items())
    result = {"source": source, "original_proof_cache_reused": reused_cache,
              "initial_generated_steps": first["generated_steps"], "retained_cache_artifacts": cache_artifacts, "originals": originals, "leaf_bytes": native["leaf_bytes"],
              "leaf_compressions": count, "identity_bytes": 80, "transaction_id": native["transaction_id"],
              "body_root": native["body_root"], "signing_hash": native["signing_hash"],
              "body_membership_verified": True, "canonical_admission": False, "signature_verified": False,
              "body_hash_profile": 3, "membership_profile": 2, "full_cache_generated_steps": 0,
              "same_ID_changed_signature_body_refused": True, "native_reference_matches_AIR": True,
              "cold_verification": True, "original_artifacts_unchanged": True,
              "mathematical_refusals": refused["refusals"], "command_refusals": 5,
              "prepared_partial_recovery": {"generated_steps": 1, "original_bytes_equal": True,
                                            "cold_verified": True, "actual_power_loss_tested": False},
              "frozen_artifacts": frozen, "fixture_signature_generated": len(sys.argv) == 3,
              "proof_stage_new_signing": False}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ["frozen_artifacts", "mathematical_refusals", "originals", "retained_cache_artifacts"]}))


if __name__ == "__main__":
    main()
