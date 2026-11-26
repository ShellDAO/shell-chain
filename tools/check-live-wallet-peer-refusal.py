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


def recover(case, provider_case):
    require(case.report.get("peerRefusalComplete") and case.report.get("copyStore") == "fresh",
            "retained failed peer copy required")
    if case.report.get("peerRecoveryComplete"):
        return
    good_manifest = provider_case.report["production"]["manifest"]
    good_id = provider_case.report["proofId"]
    require(good_manifest["blockHash"] == case.report["blockHash"]
            and good_manifest != case.report["badManifest"] and good_id != case.report["badProofId"]
            and provider_case.report["liveState"] == case.report["liveState"], "correct-source identity mismatch")
    case.report["goodManifest"] = good_manifest
    case.report["goodProofId"] = good_id
    if not case.report.get("recoveryBefore"):
        with case.node("receiver", admission=True) as (endpoint, child):
            baseline = unchanged_genesis(case, endpoint)
            failed = case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]])
            rejected = check_failure(case, endpoint, failed)
            case.report["recoveryGoodProofAbsent"] = case.rpc(endpoint, "admin_canonicalProofStatus", [good_id], reject=True)
            case.report["recoveryBefore"] = {"genesis": baseline, "admission": failed, "badIntake": rejected,
                "badFetch": case.rpc(endpoint, "admin_canonicalProofFetchStatus", [case.report["badProofId"]])}
            case.save()
    with provider_case.node("receiver") as (provider, source):
        require(provider_case.snapshot(provider) == case.report["liveState"], "honest provider Native state mismatch")
        offered = provider_case.rpc(provider, "admin_canonicalProofStatus", [good_id])
        require(offered["state"] == "verified" and offered["manifest"] == good_manifest,
                "authentic provider artifact unavailable")
        provider_case.check_history_result(offered)

        def listening():
            info = provider_case.rpc(provider, "admin_nodeInfo")
            return info if info["id"] and info["listenAddr"] else None

        info = provider_case.wait(listening, source)
        require(info["id"] != case.report["providerNodeInfo"]["id"], "independent correct peer required")
        address = info["listenAddr"]
        if "/p2p/" not in address:
            address += "/p2p/" + info["id"]
        case.report["recoveryProviderInfo"] = info
        case.save()
        with case.node("receiver", admission=True, bootnode=address) as (endpoint, child):
            def completed():
                admission = case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]])
                return admission if admission and admission["status"]["state"] == "complete" else None

            admission = case.wait(completed, child, timeout=1800)
            record = admission["status"]
            require(admission["nativeCanonical"] is True and admission["statusIsAuthorization"] is False
                    and record["attempts"] == 2 and record["manifest"] == good_manifest
                    and record["peer"] == info["id"] and record["error"] is None
                    and record["sourceHash"] == case.report["recoveryBefore"]["admission"]["status"]["sourceHash"],
                    "correct second-manifest source binding mismatch")
            case.wait(lambda: case.rpc(endpoint, "eth_getBlockByNumber", ["finalized", False])["hash"]
                      == case.report["blockHash"], child)
            actual = case.snapshot(endpoint)
            case.check_state(actual)
            require(actual == case.report["liveState"], "recovered Native receipts/accounts differ from independent original")
            verified = case.rpc(endpoint, "admin_canonicalProofStatus", [good_id])
            require(verified["state"] == "verified" and verified["result"]
                    and verified["verificationAttempts"] == 1, "authentic peer payload not freshly verified")
            case.check_history_result(verified)
            old = case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["badProofId"]])
            require(old == case.report["recoveryBefore"]["badIntake"], "recovery changed the rejected original proof")
            require(case.rpc(endpoint, "admin_canonicalProofFetchStatus", [case.report["badProofId"]])
                    == case.report["recoveryBefore"]["badFetch"], "recovery changed the old failed peer transfer")
            case.report.update(recoveredAdmission=admission, recoveredNative=actual, recoveredVerified=verified,
                               preservedBadIntake=old,
                               recoveryFetch=case.rpc(endpoint, "admin_canonicalProofFetchStatus", [good_id]))
            case.save()
        require(provider_case.snapshot(provider) == case.report["liveState"], "honest provider state changed")
        require(provider_case.rpc(provider, "admin_canonicalProofStatus", [good_id]) == offered,
                "recovery changed authentic provider proof metadata")
    with case.node("receiver", admission=True) as (endpoint, child):
        require(case.snapshot(endpoint) == case.report["recoveredNative"], "recovered Native state lost on cold restart")
        admission = case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]])
        require(admission == case.report["recoveredAdmission"], "cold recovered candidate changed")
        require(case.rpc(endpoint, "admin_canonicalProofStatus", [good_id]) == case.report["recoveredVerified"]
                and case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["badProofId"]])
                == case.report["preservedBadIntake"], "cold recovery changed good/bad proof states")
        case.report["coldRecoveredAdmission"] = admission
        case.save()
    case.report["peerRecoveryComplete"] = True
    case.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("tamper_source", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("--recover-root", type=Path, metavar="COPY_ROOT",
                        help="Copy the completed failed recipient and reconnect it to the original authentic provider")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.recover_root:
        with wallet.history_copy(binary, args.root.absolute(), args.recover_root, store_name="fresh") as target:
            with wallet.history_copy(binary, args.source.absolute(), target / "honest-provider") as honest:
                with (target / "run.lock").open("a+b") as lock, (honest / "run.lock").open("a+b") as source_lock:
                    fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.lockf(source_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    case = wallet.Case(binary, target, True)
                    provider_case = wallet.Case(binary, honest, True)
                    try:
                        case.check_scheme()
                        provider_case.check_scheme()
                        recover(case, provider_case)
                        print(json.dumps({"liveWalletPeerRecoveryComplete": True, "block": case.report["blockHash"],
                                          "attempts": case.report["recoveredAdmission"]["status"]["attempts"]}))
                    except BaseException as error:
                        case.report["error"] = str(error)
                        case.save()
                        raise
        return
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
