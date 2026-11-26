#!/usr/bin/env python3
"""Pull an unverified Ready artifact over real peers without granting Native writes.

Requires Python 3.11+, blake3 1.0.8, a matching rocksdb/libp2p shell-node,
a complete live SLH sender/proposer wallet case, and its completed inner-tamper
case. Creates a separate copy of the original default-off Native peer. Keeps
all inputs and state; resume using the same command without regenerating proofs.
"""

import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import time

import blake3

spec = importlib.util.spec_from_file_location("wallet", Path(__file__).with_name("check-live-wallet-quorum.py"))
wallet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wallet)
require = wallet.require
CHUNK = 256 * 1024
INNER_ERROR = "BLAKE3 compression verification: QuerySeedProofOfWorkVerificationFailed"


def unchanged_genesis(case, endpoint):
    snapshot = case.snapshot(endpoint, "0x0")
    require(snapshot["head"] == "0x0" and snapshot["block"]["hash"] == case.report["genesisHash"]
            and snapshot["finalized"] == case.report["genesisHash"]
            and [int(x, 16) for x in snapshot["balances"]] == [wallet.INITIAL, 0]
            and snapshot["nonces"] == ["0x0", "0x0"], "bad peer proof changed genesis Native state")
    require(case.rpc(endpoint, "eth_getTransactionReceipt", [case.report["transaction"]]) is None
            and case.rpc(endpoint, "eth_getBlockByNumber", ["0x1", False]) is None,
            "bad proof published a canonical block or receipt")
    return snapshot


def check_failure(case, endpoint, admission):
    require(admission and admission["nativeCanonical"] is False and admission["statusIsAuthorization"] is False,
            "failed peer candidate became Native canonical")
    record = admission["status"]
    require(record["state"] == "failed" and record["manifest"] == case.report["badManifest"]
            and record["peer"] == case.report["providerNodeInfo"]["id"]
            and INNER_ERROR in (record.get("error") or ""), "actual peer inner verification refusal absent")
    intake = case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["badProofId"]])
    require(intake["state"] == "rejected" and intake["result"] is None
            and intake["manifest"] == case.report["badManifest"]
            and intake["receivedBytes"] == case.report["badManifest"]["totalBytes"]
            and intake["nextChunk"] == (intake["receivedBytes"] + CHUNK - 1) // CHUNK
            and INNER_ERROR in (intake.get("error") or ""), "actual peer intake/refusal mismatch")
    return intake


def exercise(case, manifest, payload):
    require(case.proof_kind == "sender-proposer" and case.algorithm == "slhdsa", "actual SLH sender/proposer case required")
    require(manifest["blockHash"] == case.report["blockHash"] and manifest["version"] == 1
            and manifest["chainId"] == 1337 and manifest["genesisHash"] == case.report["genesisHash"]
            and manifest["totalBytes"] == len(payload)
            and manifest["payloadHash"] == "0x" + blake3.blake3(payload).hexdigest(),
            "retained bad payload source/hash mismatch")
    if case.report.get("peerRefusalComplete"):
        return
    case.report["badManifest"] = manifest
    for name in ["fresh", "control"]:
        if not (case.root / name).exists():
            case.run(name + "-init", ["--datadir", name, "init", "--genesis", "genesis.json",
                                      "--chain-id", "1337", "--network", "dev"])
    with case.node("receiver") as (provider, child):
        require(case.snapshot(provider) == case.report["liveState"], "provider copy differs from independently executed Native1")
        if not case.report.get("providerReady"):
            case.report["providerOriginalProofAbsent"] = case.rpc(
                provider, "admin_canonicalProofStatus", [case.report["proofId"]], reject=True)
        upload = case.rpc(provider, "admin_beginCanonicalProof", [manifest])
        case.report["badProofId"] = upload["proofId"]
        case.save()
        for index in range(upload["nextChunk"], (len(payload) + CHUNK - 1) // CHUNK):
            time.sleep(0.03)
            upload = case.rpc(provider, "admin_appendCanonicalProof",
                              [upload["proofId"], index, "0x" + payload[index * CHUNK:(index + 1) * CHUNK].hex()])
        require(upload["state"] == "ready" and upload["verificationAttempts"] == 0 and upload["result"] is None,
                "provider must expose only unverified Ready bytes")
        case.report["providerReady"] = upload
        def listening():
            info = case.rpc(provider, "admin_nodeInfo")
            return info if info["id"] and info["listenAddr"] else None

        info = case.wait(listening, child)
        require(info["id"] and info["listenAddr"], "provider peer identity unavailable")
        address = info["listenAddr"]
        if "/p2p/" not in address:
            address += "/p2p/" + info["id"]
        case.report["providerNodeInfo"] = info
        case.save()
        with case.node("fresh", admission=True, bootnode=address) as (endpoint, receiver):
            baseline = unchanged_genesis(case, endpoint)

            def failed():
                admission = case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]])
                require(not admission or admission["nativeCanonical"] is False, "bad proof unexpectedly authorized Native import")
                if admission and admission["status"]["state"] == "failed":
                    intake = case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["badProofId"]])
                    return admission if intake["state"] == "rejected" else None
                return None

            admission = case.wait(failed, receiver, timeout=1800)
            case.report["peerFailure"] = admission
            case.report["peerRejectedIntake"] = check_failure(case, endpoint, admission)
            case.report["peerFetch"] = case.rpc(endpoint, "admin_canonicalProofFetchStatus", [case.report["badProofId"]])
            require(case.snapshot(endpoint, "0x0") == baseline, "failed peer proof wrote Native state")
            case.report["freshGenesis"] = unchanged_genesis(case, endpoint)
            case.save()
        with case.node("control", bootnode=address) as (endpoint, receiver):
            case.wait(lambda: case.rpc(endpoint, "eth_blockNumber") == "0x1", receiver)
            case.wait(lambda: case.rpc(endpoint, "eth_getBlockByNumber", ["finalized", False])["hash"]
                      == case.report["blockHash"], receiver)
            actual = case.snapshot(endpoint)
            case.check_state(actual)
            require(actual == case.report["liveState"], "independent default-off Native receipt/account mismatch")
            require(case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]]) is None
                    and case.production(endpoint) is None, "default-off control consumed or produced a proof")
            case.report["controlNative"] = actual
            case.save()
        require(case.snapshot(provider) == case.report["liveState"], "Ready advertisement changed provider Native state")
        require(case.rpc(provider, "admin_canonicalProofStatus", [case.report["badProofId"]]) == upload,
                "provider unexpectedly verified or changed its Ready artifact")
    with case.node("fresh", admission=True) as (endpoint, receiver):
        admission = case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]])
        case.report["coldPeerFailure"] = admission
        cold = check_failure(case, endpoint, admission)
        require(cold == case.report["peerRejectedIntake"], "cold failure metadata unexpectedly changed")
        require(unchanged_genesis(case, endpoint) == case.report["freshGenesis"], "cold rejected receiver changed Native0")
        case.save()
    case.report["peerRefusalComplete"] = True
    case.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("tamper_source", type=Path)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    tamper = json.loads((args.tamper_source / "result.json").read_text())
    require(tamper.get("tamperComplete") and tamper["binarySHA256"] == wallet.digest(binary), "complete matching tamper source required")
    payload = (args.tamper_source / "tampered-payload.bin").read_bytes()
    with wallet.history_copy(binary, args.source.absolute(), args.root, store_name="native") as target:
        with (target / "run.lock").open("a+b") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            case = wallet.Case(binary, target, True)
            try:
                case.check_scheme()
                exercise(case, tamper["tamperedManifest"], payload)
                print(json.dumps({"liveWalletPeerRefusalComplete": True, "block": case.report["blockHash"],
                                  "badProofId": case.report["badProofId"]}))
            except BaseException as error:
                case.report["error"] = str(error)
                case.save()
                raise


if __name__ == "__main__":
    main()
