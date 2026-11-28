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


def mutate(payload, co_entry=None):
    quorum_prefix = b"\0commit-quorum/cbor/v2/"
    if payload.startswith(quorum_prefix):
        require(co_entry is not None, "actual mixed co-authority binding required")
        encoded = payload[len(quorum_prefix):]
        frame = cbor2.loads(encoded)
        require(cbor2.dumps(frame) == encoded and frame["version"] == 2
                and len(frame["signatures"]) == len(frame["slh_signatures"]) == 1,
                "canonical mixed two-signature quorum frame required")
        lattice = frame["signatures"][0]
        require(lattice["version"] == 1
                and lattice["equation"]["key"]["public_key"] == co_entry["publicKey"]
                and lattice["equation"]["signature"]["signature"] == co_entry["signature"],
                "actual ML-DSA co-authority key/signature mismatch")
        decoder = lattice["equation"]["signature"]
        raw = decoder["proof_bytes"]
        require(isinstance(raw, list) and 8 < len(raw) <= 1_048_576
                and all(isinstance(v, int) and 0 <= v <= 255 for v in raw), "bounded decoder proof required")
        before = raw[-1]
        raw[-1] ^= 1
        changed = quorum_prefix + cbor2.dumps(frame)
        after = raw[-1]
        raw[-1] = before
        require(cbor2.dumps(frame) == encoded, "mutation changed another quorum field")
        require(len(changed) == len(payload) and changed != payload, "quorum mutation changed geometry")
        return changed, {"path": ["signatures", 0, "equation", "signature", "proof_bytes"],
                         "coAuthority": co_entry["address"], "innerProofBytes": len(raw),
                         "changedOffset": len(raw) - 1, "beforeByte": before, "afterByte": after,
                         "mutation": "one bit in Winterfell serialized trailing u64 decoder proof nonce",
                         "expectedVerifierError": "signature encoding: decoder verification: QuerySeedProofOfWorkVerificationFailed",
                         "frame": quorum_prefix.decode("ascii")}
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
            and case.report["mutation"].get("expectedVerifierError", "BLAKE3 compression verification:")
            in (status.get("error") or ""),
            "expected inner STARK verification refusal; inspect the retained first result")


def unchanged_current(case, endpoint):
    require(case.snapshot(endpoint, "0x2") == case.report["advancedState"], "inner proof changed current Native state")
    if case.report.get("mixedWeighted"):
        account = [case.rpc(endpoint, method, [case.report["cosigner"], "latest"])
                   for method in ["eth_getBalance", "eth_getTransactionCount"]]
        require(account == case.report["advancedCosignerState"], "inner proof changed co-authority fee/nonce")


def exercise(case):
    require(case.report.get("advancedHistoryComplete"), "real advanced-history source required")
    require(case.proof_kind == "sender-proposer"
            or (case.proof_kind == "quorum" and case.report.get("mixedWeighted")),
            "sender/proposer or actual mixed-quorum source artifact required")
    if case.report.get("tamperComplete"):
        return
    with case.node("receiver") as (endpoint, child):
        golden = case.report["advancedState"]
        unchanged_current(case, endpoint)
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
            co_entry = None
            if case.proof_kind == "quorum":
                key = json.loads((case.root / "cosigner.json").read_text())["public_key"]
                signature = case.report["liveCertificate"]["certificate"][case.report["cosigner"]]
                require(signature["sig_type"] == "MlDsa65", "actual ML-DSA co-authority signature required")
                co_entry = {"address": case.report["cosigner"],
                            "publicKey": list(bytes.fromhex(key.removeprefix("0x"))), "signature": signature["data"]}
            changed, observation = mutate(payload, co_entry)
            mutated_file.write_bytes(changed)
            case.report["mutation"] = observation
            case.save()
        changed = mutated_file.read_bytes()
        altered = dict(manifest, payloadHash=payload_hash(changed))
        require(len(changed) == manifest["totalBytes"] and altered["payloadHash"] != manifest["payloadHash"],
                "mutated artifact hash/geometry mismatch")
        require(len(changed) <= 256 * 1024 * 1024 and 2 * len(changed) <= 512 * 1024 * 1024,
                "good and bad artifacts exceed the original object/cache bounds")
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
        unchanged_current(case, endpoint)
        require(case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["proofId"]]) == original,
                "mutated artifact changed authentic original intake/result")
    with case.node("receiver") as (endpoint, child):
        check_rejected(case, endpoint, child, "coldTamper")
        unchanged_current(case, endpoint)
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
