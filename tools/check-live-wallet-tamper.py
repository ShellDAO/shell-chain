#!/usr/bin/env python3
"""Reject a rehashed inner STARK mutation without changing current Native state.

Requires Python 3.11+, blake3 1.0.8 and cbor2 6.3.0, plus a matching
rocksdb/libp2p shell-node and a completed --history-after-advance source case.
Creates a separate closed-receiver copy. Retains every input, key, and receipt.
Resume with the same command; never recreate its authentic source or proof.
"""

import argparse
import fcntl
import importlib.util
import json
import time
from pathlib import Path

import blake3
import cbor2

spec = importlib.util.spec_from_file_location("wallet", Path(__file__).with_name("check-live-wallet-quorum.py"))
wallet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wallet)
require = wallet.require
CHUNK = 256 * 1024


def payload_hash(data):
    return "0x" + blake3.blake3(data).hexdigest()


def mutate(payload):
    marker = b"\0canonical-proof/cbor/"
    require(payload.startswith(marker), "compact canonical artifact required")
    end = payload.find(b"/", len(marker)) + 1
    prefix, encoded = payload[:end], payload[end:]
    require(prefix in [marker + b"v11/", marker + b"v12/"], "tested SLH sender/proposer frame11/12 required")
    frame = cbor2.loads(encoded)
    require(cbor2.dumps(frame) == encoded, "original frame CBOR roundtrip mismatch")
    for index, certificate in enumerate(frame["certificates"]):
        require(certificate["hash"] == blake3.blake3(certificate["data"]).digest(), "original certificate hash mismatch")
        value = cbor2.loads(certificate["data"])
        group = value.get("compression_group") if isinstance(value, dict) else None
        if not group:
            continue
        require(cbor2.dumps(value) == certificate["data"], "original certificate CBOR roundtrip mismatch")
        proof = group[0]["proof_bytes"]
        require(isinstance(proof, bytes) and len(proof) > 8, "bounded inner Winterfell proof bytes required")
        changed = bytearray(proof)
        changed[-1] ^= 1
        group[0]["proof_bytes"] = bytes(changed)
        before_hash = certificate["hash"]
        certificate["data"] = cbor2.dumps(value)
        certificate["hash"] = blake3.blake3(certificate["data"]).digest()
        result = prefix + cbor2.dumps(frame)
        require(len(result) == len(payload) and result != payload, "mutation must preserve artifact geometry")
        return result, {"certificate": index, "path": ["compression_group", 0, "proof_bytes"],
                        "innerProofBytes": len(proof), "changedOffset": len(proof) - 1,
                        "beforeByte": proof[-1], "afterByte": changed[-1],
                        "beforeCertificateHash": "0x" + before_hash.hex(),
                        "afterCertificateHash": "0x" + certificate["hash"].hex(),
                        "mutation": "one bit in Winterfell serialized trailing u64 proof nonce",
                        "frame": prefix.decode("ascii")}
    raise RuntimeError("actual compression-group certificate unavailable; no mutation performed")


def check_rejected(case, endpoint, child, label):
    proof_id = case.report["tamperedProofId"]
    before = case.rpc(endpoint, "admin_canonicalProofStatus", [proof_id])
    response = case.rpc(endpoint, "admin_verifyCanonicalProof", [proof_id, True])
    case.report[label + "Request"] = {"before": before, "response": response}
    case.save()

    def finished():
        status = case.rpc(endpoint, "admin_canonicalProofStatus", [proof_id])
        if status["state"] in ["verified", "rejected"]:
            return status
        return None

    status = case.wait(finished, child)
    case.report[label + "Rejection"] = status
    case.save()
    require(response["state"] == "verifying" and response["result"] is None,
            "verification must claim the actual persisted complete payload")
    require(status["state"] == "rejected" and status["result"] is None
            and status["verificationAttempts"] == before["verificationAttempts"] + 1
            and "BLAKE3 compression verification:" in (status.get("error") or ""),
            "expected inner BLAKE3 STARK verification refusal; inspect the retained first result")


def exercise(case):
    require(case.report.get("advancedHistoryComplete"), "real advanced-history source required")
    require(case.proof_kind == "sender-proposer", "sender/proposer source artifact required")
    if case.report.get("tamperComplete"):
        return
    with case.node("receiver") as (endpoint, child):
        golden = case.report["advancedState"]
        require(case.snapshot(endpoint, "0x2") == golden, "copy differs from actual advanced Native state")
        original = case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["proofId"]])
        require(original["state"] == "verified" and original["result"], "authentic full proof required")
        case.check_history_result(original, golden["block"]["hash"])
        case.report["originalIntake"] = original
        manifest = original["manifest"]
        original_file = case.root / "original-payload.bin"
        if not original_file.exists():
            partial = original_file.with_suffix(".part")
            received = partial.stat().st_size if partial.exists() else 0
            require(received <= manifest["totalBytes"]
                    and (received % CHUNK == 0 or received == manifest["totalBytes"]),
                    "incomplete downloaded chunk; retain prefix for inspection")
            with partial.open("ab") as stream:
                for index in range((received + CHUNK - 1) // CHUNK, original["nextChunk"]):
                    time.sleep(0.03)
                    data = case.rpc(endpoint, "admin_getCanonicalProofChunk", [case.report["proofId"], index])
                    stream.write(bytes.fromhex(data.removeprefix("0x")))
            partial.replace(original_file)
        payload = original_file.read_bytes()
        require(len(payload) == manifest["totalBytes"] and payload_hash(payload) == manifest["payloadHash"],
                "authentic retained payload mismatch")
        mutated_file = case.root / "tampered-payload.bin"
        if not mutated_file.exists():
            changed, observation = mutate(payload)
            mutated_file.write_bytes(changed)
            case.report["mutation"] = observation
            case.save()
        changed = mutated_file.read_bytes()
        altered = dict(manifest, payloadHash=payload_hash(changed))
        require(len(changed) == manifest["totalBytes"] and altered["payloadHash"] != manifest["payloadHash"],
                "mutated artifact hash/geometry mismatch")
        case.report["tamperedManifest"] = altered
        status = case.rpc(endpoint, "admin_beginCanonicalProof", [altered])
        case.report["tamperedProofId"] = status["proofId"]
        case.save()
        for index in range(status["nextChunk"], (len(changed) + CHUNK - 1) // CHUNK):
            time.sleep(0.03)
            status = case.rpc(endpoint, "admin_appendCanonicalProof",
                              [status["proofId"], index, "0x" + changed[index * CHUNK:(index + 1) * CHUNK].hex()])
        case.report["tamperedUpload"] = status
        case.save()
        require(status["receivedBytes"] == len(changed), "incomplete mutated payload")
        if not case.report.get("hotTamperRejection"):
            check_rejected(case, endpoint, child, "hotTamper")
        require(case.snapshot(endpoint, "0x2") == golden, "rejected inner proof changed current Native state")
        require(case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["proofId"]]) == original,
                "mutated artifact changed authentic original intake/result")
    with case.node("receiver") as (endpoint, child):
        check_rejected(case, endpoint, child, "coldTamper")
        require(case.snapshot(endpoint, "0x2") == case.report["advancedState"], "cold rejection changed current Native state")
        require(case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["proofId"]]) == case.report["originalIntake"],
                "cold mutated artifact changed authentic intake/result")
    case.report["tamperComplete"] = True
    case.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with wallet.history_copy(binary, args.source.absolute(), args.root) as target:
        with (target / "run.lock").open("a+b") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            case = wallet.Case(binary, target, True)
            try:
                case.check_scheme()
                exercise(case)
                print(json.dumps({"liveWalletInnerTamperRejected": True, "proofId": case.report["tamperedProofId"]}))
            except BaseException as error:
                case.report["error"] = str(error)
                case.save()
                raise


if __name__ == "__main__":
    main()
