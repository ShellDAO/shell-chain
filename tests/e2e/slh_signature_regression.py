"""Complete real17-layer SLH signature proof, immutable recovery and refusals."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
from slh_fors_regression import reference, reference_xmss


def main():
    binary, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if out.exists():
        raise RuntimeError("original full SLH regression output already exists")
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
        return json.loads(log.read_text().splitlines()[-1]) if expected == 0 and structured else None

    if len(sys.argv) in [5, 6]:
        fors_input, fors_proof = Path(sys.argv[3]).resolve(), Path(sys.argv[4]).resolve()
        imported = [Path(sys.argv[5]).resolve()] if len(sys.argv) == 6 else []
        source = "retained original public signature/FORS, optional retained layer0; no signing"
    elif len(sys.argv) == 3:
        run("prepare-fors", ["bash", "tests/e2e/slh-fors.sh", out / "fors"], structured=False)
        fors_input, fors_proof = out / "fors/input.json", out / "fors/proof/fors.cbor"
        imported = []
        source = "separate self-contained genuine memory-only signature fixture"
    else:
        raise RuntimeError("usage: binary output [fors-input.json fors.cbor [layer0.cbor]]")
    originals = {str(p): sha(p) for p in [fors_input, fors_proof, *imported]}
    full = json.loads(fors_input.read_text())
    forest = reference(full)
    root = bytes(forest["fors_public_key"])
    tree, leaf = forest["tree"], forest["leaf"]
    roots = []
    for at in range(17):
        if at:
            leaf, tree = tree & 15, tree >> 4
        start = 11_232 + at * 2272
        root = reference_xmss({"public_seed": full["public_seed"], "message": list(root),
                               "layer": at, "tree": tree, "leaf": leaf,
                               "signature": full["signature"][start:start + 2272]})
        roots.append(list(root))
    assert tree == 0 and root == bytes(full["public_root"])
    proofdir = out / "proof"
    run("init", [binary, "init", fors_input, proofdir, fors_proof, *imported])
    first = run("prove", [binary, "prove", fors_input, proofdir])
    assert first["layer_roots"] == roots and first["root"] == full["public_root"]
    assert first["full_signature_verified"] and first["layers"] == 17 and not first["canonical_admission"]
    assert first["recovered_layers"] == len(imported) and first["generated_steps"] > 0
    frozen = {str(p.relative_to(proofdir)): sha(p) for p in proofdir.rglob("*") if p.is_file()}
    cold = run("cold-verify", [binary, "verify", fors_input, proofdir])
    assert cold["layer_roots"] == roots and cold["full_signature_verified"]
    resumed = run("resume", [binary, "resume", fors_input, proofdir])
    assert resumed["layer_roots"] == roots and resumed["generated_steps"] == 0
    assert resumed["recovered_layers"] == 17
    refusals = run("mathematical-refusals", [binary, "refusals", fors_input, proofdir])
    assert len(refusals["refusals"]) == 20 and all(x["error"] for x in refusals["refusals"])
    run("overwrite-refused", [binary, "prove", fors_input, proofdir], 1)
    run("init-replacement-refused", [binary, "init", fors_input, proofdir, fors_proof], 1)
    wrong = json.loads(fors_input.read_text())
    wrong["message"][0] ^= 1
    changed = out / "wrong-input.json"
    changed.write_text(json.dumps(wrong) + "\n")
    run("wrong-input-refused", [binary, "verify", changed, proofdir], 1)
    run("resume-replacement-refused", [binary, "resume", changed, proofdir], 1)

    # A separate view copies only independent full certificates. Alterations
    # never write into the original inputs, component proofs or checkpoints.
    for label, manifest in [("trailing", (proofdir / "signature.cbor").read_bytes() + b"\0"),
                            ("corrupt", b"invalid certificate")]:
        target = out / label
        target.mkdir()
        shutil.copyfile(proofdir / "inputs.json", target / "inputs.json")
        shutil.copyfile(proofdir / "fors.cbor", target / "fors.cbor")
        (target / "signature.cbor").write_bytes(manifest)
        run(label + "-refused", [binary, "verify", fors_input, target], 1)

    # Prepare a real missing-final-hash boundary. This is deliberately not a
    # claim about process termination or power loss. Resume reuses the original
    # sixteen whole layers and the last layer's verified retained prefix.
    partial = out / "partial-recovery"
    shutil.copytree(proofdir, partial, ignore=lambda directory, names:
                    [n for n in names if (Path(directory) == proofdir and n == "signature.cbor")
                     or (Path(directory) == proofdir / "layer-16" and n in ["xmss.cbor", "hash-004.cbor"])])
    retained = {str(p.relative_to(partial)): sha(p) for p in partial.rglob("*") if p.is_file()}
    recovered = run("partial-resume", [binary, "resume", fors_input, partial])
    assert recovered["layer_roots"] == roots and recovered["generated_steps"] == 1
    assert recovered["recovered_layers"] == 16 and recovered["recovered_steps"] > 0
    partial_cold = run("partial-cold-verify", [binary, "verify", fors_input, partial])
    assert partial_cold["layer_roots"] == roots
    assert all(sha(partial / n) == h for n, h in retained.items())
    assert sha(partial / "signature.cbor") == sha(proofdir / "signature.cbor")
    assert sha(partial / "layer-16/xmss.cbor") == sha(proofdir / "layer-16/xmss.cbor")
    assert all(sha(proofdir / n) == h for n, h in frozen.items())
    assert all(sha(Path(n)) == h for n, h in originals.items())
    result = {"source": source, "actual_layers_proved": 17,
              "WOTS_chains_per_layer": 67, "authentication_levels_per_layer": 4,
              "root": full["public_root"], "layer_roots": roots,
              "independent_hashlib_all_layers_match": True, "original_artifacts_unchanged": True,
              "generated_steps": first["generated_steps"], "recovered_steps": first["recovered_steps"],
              "imported_original_layers": len(imported), "cold_verification": True,
              "cache_resume_no_replacement": True, "full_cache_generated_steps": 0,
              "mathematical_refusals": refusals["refusals"], "command_refusals": 6,
              "prepared_partial_recovery": {"whole_layers_reused": 16, "generated_steps": 1,
                                             "original_bytes_equal": True, "cold_verification": True,
                                             "actual_power_loss_tested": False},
              "frozen_artifacts": frozen, "original_inputs": originals,
              "full_signature_verified": True, "canonical_admission": False,
              "proof_stage_new_signing": False, "fixture_signature_generated": len(sys.argv) == 3}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ["frozen_artifacts", "original_inputs", "mathematical_refusals", "layer_roots"]}))


if __name__ == "__main__":
    main()
