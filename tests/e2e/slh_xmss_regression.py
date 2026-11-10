"""Complete actual67-chain/four-level XMSS proof and immutable cache regression."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
from slh_fors_regression import reference, reference_hypertree, reference_xmss


def main():
    binary, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if out.exists():
        raise RuntimeError("original XMSS regression output already exists")
    out.mkdir()
    commands = out / "commands"
    commands.mkdir()

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run(label, args, expected=0, structured=True):
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
        return json.loads(log.read_text()) if expected == 0 and structured else None

    if len(sys.argv) == 5:
        fors_input, fors_proof = Path(sys.argv[3]).resolve(), Path(sys.argv[4]).resolve()
        source = "retained original FORS inputs and proof, no signing or FORS regeneration"
    elif len(sys.argv) == 3:
        run("prepare-fors", ["bash", "tests/e2e/slh-fors.sh", out / "fors"], structured=False)
        fors_input, fors_proof = out / "fors/input.json", out / "fors/proof/fors.cbor"
        source = "self-contained memory-only genuine signature/FORS fixture"
    else:
        raise RuntimeError("usage: binary output [fors-input.json fors.cbor]")
    originals = {str(p): sha(p) for p in [fors_input, fors_proof]}
    layer = out / "layer.json"
    run("from-fors", [binary, "from-fors", fors_input, fors_proof, layer])
    full = json.loads(fors_input.read_text())
    forest = reference(full)
    assert reference_hypertree(full, forest) == bytes(full["public_root"])
    value = json.loads(layer.read_text())
    assert value == {"public_seed": full["public_seed"], "message": forest["fors_public_key"],
                     "layer": 0, "tree": forest["tree"], "leaf": forest["leaf"],
                     "signature": full["signature"][11_232:13_504]}
    expected = reference_xmss(value)
    proofdir = out / "proof"
    first = run("prove", [binary, "prove", layer, proofdir])
    count = first["F_batches"] + 6
    assert first["generated_steps"] == count and first["recovered_steps"] == 0
    assert bytes(first["root"]) == expected and first["verified"] and not first["full_signature_verified"]
    proof = proofdir / "xmss.cbor"
    frozen = {p.name: sha(p) for p in proofdir.iterdir() if p.is_file()}
    cold = run("cold-verify", [binary, "verify", layer, proof])
    assert bytes(cold["root"]) == expected
    resumed = run("resume", [binary, "resume", layer, proofdir])
    assert resumed["generated_steps"] == 0 and resumed["recovered_steps"] == count
    assert bytes(resumed["root"]) == expected
    refusals = run("mathematical-refusals", [binary, "refusals", layer, proof])
    assert len(refusals["refusals"]) == 15 and all(x["error"] for x in refusals["refusals"])
    run("overwrite-refused", [binary, "prove", layer, proofdir], 1)
    wrong = json.loads(layer.read_text())
    wrong["message"][0] ^= 1
    changed = out / "wrong-layer.json"
    changed.write_text(json.dumps(wrong) + "\n")
    run("wrong-input-refused", [binary, "verify", changed, proof], 1)
    run("resume-replacement-refused", [binary, "resume", changed, proofdir], 1)
    data = bytearray(proof.read_bytes())
    data[len(data) // 2] ^= 1
    corrupt = out / "corrupt.cbor"
    corrupt.write_bytes(data)
    run("corrupt-proof-refused", [binary, "verify", layer, corrupt], 1)
    trailing = out / "trailing.cbor"
    trailing.write_bytes(proof.read_bytes() + b"\0")
    run("trailing-refused", [binary, "verify", layer, trailing], 1)
    assert all(sha(Path(p)) == h for p, h in originals.items())
    assert all(sha(proofdir / p) == h for p, h in frozen.items())
    result = {"source": source, "layer": 0, "actual_layers_proved": 1,
              "WOTS_chains": 67, "XMSS_authentication_levels": 4,
              "F_batches": first["F_batches"], "checkpoint_steps": count,
              "root": list(expected), "proof_bytes": proof.stat().st_size,
              "proof_sha256": sha(proof), "frozen_artifacts": frozen,
              "independent_hashlib_layer_match": True,
              "independent_unproved_full_hypertree_matches_public_root": True,
              "cold_verification": True, "cache_resume_no_replacement": True,
              "mathematical_refusals": refusals["refusals"], "command_refusals": 5,
              "original_FORS_inputs_and_proof_unchanged": True,
              "full_signature_verified": False, "canonical_admission": False}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ["frozen_artifacts", "mathematical_refusals"]}))


if __name__ == "__main__":
    main()
