"""Real fixed35-tree FORS proof, persistence and independent hashlib regression."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys


def reference(value):
    sig = bytes(value["signature"])
    seed = bytes(value["public_seed"])
    root = bytes(value["public_root"])
    message = bytes(value["message"])
    inner = hashlib.sha512(sig[:32] + seed + root + b"\0\0" + message).digest()
    digest = hashlib.sha512(sig[:32] + seed + inner + b"\0" * 4).digest()[:49]
    bits = "".join(f"{x:08b}" for x in digest[:40])
    indices = [int(bits[i * 9:i * 9 + 9], 2) for i in range(35)]
    tree = int.from_bytes(digest[40:48], "big")
    leaf = digest[48] & 15

    def address(kind, height=0, index=0):
        return (b"\0" + tree.to_bytes(8, "big") + bytes([kind])
                + leaf.to_bytes(4, "big") + height.to_bytes(4, "big")
                + index.to_bytes(4, "big"))

    roots = []
    for i, index in enumerate(indices):
        start = 32 + i * 320
        global_index = i * 512 + index
        node = hashlib.sha256(seed + b"\0" * 32 + address(3, 0, global_index)
                              + sig[start:start + 32]).digest()
        for level in range(9):
            sibling = sig[start + (level + 1) * 32:start + (level + 2) * 32]
            pair = sibling + node if (index >> level) & 1 else node + sibling
            global_index //= 2
            node = hashlib.sha512(seed + b"\0" * 96 + address(3, level + 1, global_index)
                                  + pair).digest()[:32]
        roots.append(node)
    key = hashlib.sha512(seed + b"\0" * 96 + address(4) + b"".join(roots)).digest()[:32]
    return {"message_digest": list(digest), "tree": tree, "leaf": leaf,
            "indices": indices, "fors_public_key": list(key)}


def reference_hypertree(value, forest):
    """Independent native-hash oracle only; this is never proof acceptance."""
    seed = bytes(value["public_seed"])
    sig = bytes(value["signature"])
    current = bytes(forest["fors_public_key"])
    tree, leaf = forest["tree"], forest["leaf"]
    for layer in range(17):
        if layer:
            leaf, tree = tree & 15, tree >> 4
        start = 11_232 + layer * 2272

        def address(kind, key_pair, height, index):
            return (bytes([layer]) + tree.to_bytes(8, "big") + bytes([kind])
                    + key_pair.to_bytes(4, "big") + height.to_bytes(4, "big")
                    + index.to_bytes(4, "big"))

        digits = [n for b in current for n in (b >> 4, b & 15)]
        checksum = sum(15 - x for x in digits)
        digits.extend([checksum >> 8, (checksum >> 4) & 15, checksum & 15])
        nodes = []
        for chain, first in enumerate(digits):
            node = sig[start + chain * 32:start + (chain + 1) * 32]
            for step in range(first, 15):
                node = hashlib.sha256(seed + b"\0" * 32
                                      + address(0, leaf, chain, step) + node).digest()
            nodes.append(node)
        current = hashlib.sha512(seed + b"\0" * 96 + address(1, leaf, 0, 0)
                                 + b"".join(nodes)).digest()[:32]
        for level in range(4):
            auth = sig[start + (67 + level) * 32:start + (68 + level) * 32]
            pair = auth + current if (leaf >> level) & 1 else current + auth
            current = hashlib.sha512(seed + b"\0" * 96
                                     + address(2, 0, level + 1, leaf >> (level + 1))
                                     + pair).digest()[:32]
    return current


def main():
    binary = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]).resolve()
    if out.exists():
        raise RuntimeError("original FORS regression output already exists")
    out.mkdir()
    commands = out / "commands"
    commands.mkdir()

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run(label, args, expected=0):
        args = [str(x) for x in args]
        log = commands / (label + ".log")
        record = {"cwd": str(Path.cwd()), "argv": args,
                  "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "log": str(log), "expected_exit_code": expected}
        with log.open("x") as stream:
            process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT)
            record["pid"] = process.pid
            (commands / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
            record["exit_code"] = process.wait()
        record["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (commands / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
        if process.returncode != expected:
            raise RuntimeError(f"{label}: expected {expected}, got {process.returncode}; see {log}")
        return json.loads(log.read_text()) if expected == 0 else None

    inp = out / "input.json"
    if len(sys.argv) == 5:
        signed, public_key = Path(sys.argv[3]).resolve(), Path(sys.argv[4]).resolve()
        originals = {str(p): sha(p) for p in [signed, public_key]}
        run("native-export", [binary, "native-input", signed, public_key, inp])
        source = "retained Native public signature; no signing"
    elif len(sys.argv) == 3:
        originals = {}
        run("sample", [binary, "sample", inp])
        source = "fresh memory-only genuine signature; standalone crypto, not Native chain execution"
    else:
        raise RuntimeError("usage: binary output [signed.json public-key.json]")
    input_hash = sha(inp)
    proofdir = out / "proof"
    first = run("prove", [binary, "prove", inp, proofdir])
    assert first["generated_steps"] == 352 and first["recovered_steps"] == 0
    expected = reference(json.loads(inp.read_text()))
    assert reference_hypertree(json.loads(inp.read_text()), expected) == bytes(json.loads(inp.read_text())["public_root"])
    assert first["output"] == expected and first["verified"] and not first["full_signature_verified"]
    proof = proofdir / "fors.cbor"
    frozen = {str(p.relative_to(proofdir)): sha(p) for p in proofdir.iterdir() if p.is_file()}
    assert len(frozen) == 354
    cold = run("cold-verify", [binary, "verify", inp, proof])
    assert cold["output"] == expected and cold["verified"]
    resumed = run("resume", [binary, "resume", inp, proofdir])
    assert resumed["recovered_steps"] == 352 and resumed["generated_steps"] == 0
    assert resumed["output"] == expected
    refusals = run("mathematical-refusals", [binary, "refusals", inp, proof])
    assert len(refusals["refusals"]) >= 16 and all(x["error"] for x in refusals["refusals"])
    run("overwrite-refused", [binary, "prove", inp, proofdir], 1)
    wrong = json.loads(inp.read_text())
    wrong["message"][0] ^= 1
    wrong_path = out / "wrong-input.json"
    wrong_path.write_text(json.dumps(wrong) + "\n")
    run("wrong-input-refused", [binary, "verify", wrong_path, proof], 1)
    run("resume-input-replacement-refused", [binary, "resume", wrong_path, proofdir], 1)
    corrupt = out / "corrupt.cbor"
    data = bytearray(proof.read_bytes())
    data[len(data) // 2] ^= 1
    corrupt.write_bytes(data)
    run("corrupt-proof-refused", [binary, "verify", inp, corrupt], 1)
    trailing = out / "trailing.cbor"
    trailing.write_bytes(proof.read_bytes() + b"\0")
    run("trailing-proof-refused", [binary, "verify", inp, trailing], 1)
    # A separately named corrupt recovery copy preserves the original directory.
    bad_cache = out / "corrupt-recovery"
    bad_cache.mkdir()
    shutil.copyfile(proofdir / "inputs.json", bad_cache / "inputs.json")
    data = bytearray((proofdir / "step-000.cbor").read_bytes())
    data[len(data) // 2] ^= 1
    (bad_cache / "step-000.cbor").write_bytes(data)
    run("corrupt-step-refused", [binary, "resume", inp, bad_cache], 1)
    assert not (bad_cache / "fors.cbor").exists()
    assert sha(inp) == input_hash
    assert all(sha(proofdir / n) == h for n, h in frozen.items())
    assert all(sha(Path(n)) == h for n, h in originals.items())
    result = {"source": source, "fixed_fors_trees": 35, "authentication_levels": 9,
              "verified_hash_steps": 352, "output": expected, "independent_hashlib_match": True,
              "cold_verification": True, "all_352_cached_steps_reverified_without_replacement": True,
              "independent_unproved_hypertree_oracle_matches_native_public_root": True,
              "mathematical_refusals": refusals["refusals"], "command_refusals": 6,
              "proof_sha256": sha(proof), "proof_bytes": proof.stat().st_size,
              "frozen_artifacts": frozen, "original_inputs_unchanged": True,
              "full_signature_verified": False, "canonical_admission": False}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ["frozen_artifacts", "mathematical_refusals"]}))


if __name__ == "__main__":
    main()
