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
import hashlib
import json
from pathlib import Path
import signal
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


def closed_store(case):
    """Read closed RocksDB column families without starting Node or writing keys."""
    from rocksdict import AccessType, Options, Rdict

    path = case.root / "receiver" / "db"
    files = lambda: {str(p.relative_to(path)): wallet.digest(p) for p in path.rglob("*") if p.is_file()}
    before = files()
    native = hashlib.sha256()
    count = 0
    with (path / "LOCK").open("r+b") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = Rdict(str(path), options=Options(raw_mode=True), access_type=AccessType.read_only())
        try:
            families = sorted(Rdict.list_cf(str(path), Options(raw_mode=True)))
            require(families == ["chain", "default", "index", "receipts", "state", "witness"],
                    "unexpected RocksDB column families")
            for name in families:
                cf = db.get_column_family(name)
                try:
                    for key, value in cf.items():
                        if not key.startswith(b"local/"):
                            for part in [name.encode(), key, value]:
                                native.update(len(part).to_bytes(8, "big"))
                                native.update(part)
                            count += 1
                finally:
                    cf.close()
            state = db.get_column_family("state")
            try:
                block = bytes.fromhex(case.report["blockHash"][2:])
                admission_prefix = b"local/canonical-admission/v1/"
                body = state[admission_prefix + b"body/" + block]
                record = json.loads(state[admission_prefix + b"record/" + block])
                require("0x" + blake3.blake3(body).hexdigest() == record["sourceHash"],
                        "closed candidate body/source mismatch")
                proofs = {}
                for label in ["bad", "good"]:
                    proof_id = case.report.get(label + "ProofId")
                    if not proof_id:
                        continue
                    raw_id = bytes.fromhex(proof_id[2:])
                    prefix = b"local/canonical-proof-upload/v1/"
                    raw = state.get(prefix + b"object/" + raw_id)
                    if raw is None:
                        continue
                    status = json.loads(raw)
                    generation = status.get("generation", 0)
                    chunk_prefix = (prefix + b"generation-data/" + raw_id + generation.to_bytes(8, "big")
                                    if generation else prefix + b"data/" + raw_id)
                    payload, size, chunks = blake3.blake3(), 0, []
                    for index in range(status["nextChunk"]):
                        chunk = state[chunk_prefix + index.to_bytes(4, "big")]
                        payload.update(chunk)
                        size += len(chunk)
                        chunks.append(hashlib.sha256(chunk).hexdigest())
                    require(size == status["receivedBytes"] == status["manifest"]["totalBytes"]
                            and "0x" + payload.hexdigest() == status["manifest"]["payloadHash"],
                            "closed proof chunks/manifest mismatch")
                    fetch = state.get(prefix + b"fetch/" + raw_id)
                    proofs[label] = {"status": status, "chunkSHA256": chunks,
                                     "fetch": json.loads(fetch) if fetch else None}
                result = {"nativeSHA256": native.hexdigest(), "nativeRows": count,
                          "head": "0x" + state[b"HEAD"].hex(), "admission": record,
                          "bodySHA256": hashlib.sha256(body).hexdigest(), "proofs": proofs}
            finally:
                state.close()
        finally:
            db.close()
    after = files()
    # RocksDict may add its own format sidecar on the first foreign-store read.
    require(all(after.get(k) == v for k, v in before.items())
            and set(after) - set(before) <= {"rocksdict-config.json"}, "read-only inspection changed database files")
    result["readerSidecarCreated"] = "rocksdict-config.json" in set(after) - set(before)
    result["databaseFilesUnchanged"] = True
    return result


def interrupt_recovery(case, address):
    if not case.report.get("processLoss"):
        require(not case.report.get("processLossAttempted"), "previous crash boundary inconclusive; do not repeat the signal")
        case.report["processLossAttempted"] = True
        case.save()
        with case.node("receiver", admission=True, bootnode=address,
                       expected_exit_codes=(0, -signal.SIGKILL)) as (endpoint, child):
            deadline = time.monotonic() + 1800
            while True:
                require(child.poll() is None, "recipient exited before the crash boundary")
                admission = case.rpc(endpoint, "admin_canonicalProofAdmission", [case.report["blockHash"]])
                record = admission["status"] if admission else {}
                require(record.get("state") != "complete"
                        and not (record.get("state") == "failed" and record["attempts"] == 2),
                        "crash boundary missed; retain this prefix")
                if record.get("state") == "verifying":
                    status = case.rpc(endpoint, "admin_canonicalProofStatus", [case.report["goodProofId"]])
                    if status["state"] == "verifying":
                        require(admission["nativeCanonical"] is False and admission["statusIsAuthorization"] is False
                                and record["attempts"] == 2 and record["manifest"] == case.report["goodManifest"]
                                and record["peer"] == case.report["recoveryProviderInfo"]["id"]
                                and status["verificationAttempts"] == 1 and status["result"] is None
                                and status["manifest"] == case.report["goodManifest"]
                                and status["receivedBytes"] == case.report["goodManifest"]["totalBytes"],
                                "unexpected interrupted verification claim")
                        native = unchanged_genesis(case, endpoint)
                        case.report["processLoss"] = {"pid": child.pid, "signal": int(signal.SIGKILL),
                            "observedAt": time.time(), "admission": admission, "intake": status, "native": native}
                        case.save()
                        require(child.poll() is None, "recipient exited before its owned signal")
                        child.send_signal(signal.SIGKILL)
                        require(child.wait(timeout=120) == -signal.SIGKILL, "own recipient did not exit from SIGKILL")
                        break
                require(time.monotonic() < deadline, "verification claim timed out; do not repeat the crash attempt")
                time.sleep(0.05)
    loss = case.report["processLoss"]
    require(any(row.get("pid") == loss["pid"] and row.get("exitCode") == -signal.SIGKILL
                for row in case.report["commands"]), "own signal lacks a completed command receipt")
    if not case.report.get("interruptedStore"):
        closed = closed_store(case)
        baseline = case.report["closedBaseline"]
        require(closed["nativeSHA256"] == baseline["nativeSHA256"] and closed["head"] == case.report["genesisHash"]
                and closed["admission"] == loss["admission"]["status"]
                and closed["bodySHA256"] == baseline["bodySHA256"]
                and closed["proofs"]["good"]["status"] == loss["intake"]
                and closed["proofs"]["bad"] == baseline["proofs"]["bad"],
                "durable interrupted claim/chunks or Native0 mismatch")
        case.report["interruptedStore"] = closed
        case.save()


def recover(case, provider_case, crash_after_claim=False):
    require(case.report.get("peerRefusalComplete") and case.report.get("copyStore") == "fresh",
            "retained failed peer copy required")
    require(crash_after_claim or not case.report.get("processLossAttempted"),
            "resume this interrupted case with --crash-after-claim")
    if case.report.get("peerRecoveryComplete"):
        require(not crash_after_claim or case.report.get("crashRecoveryComplete"),
                "completed happy recovery cannot establish process loss")
        return
    good_manifest = provider_case.report["production"]["manifest"]
    good_id = provider_case.report["proofId"]
    require(good_manifest["blockHash"] == case.report["blockHash"]
            and good_manifest != case.report["badManifest"] and good_id != case.report["badProofId"]
            and provider_case.report["liveState"] == case.report["liveState"], "correct-source identity mismatch")
    case.report["goodManifest"] = good_manifest
    case.report["goodProofId"] = good_id
    if crash_after_claim and not case.report.get("closedBaseline"):
        case.report["closedBaseline"] = closed_store(case)
        case.save()
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
        if crash_after_claim:
            interrupt_recovery(case, address)
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
                    and verified["verificationAttempts"] == (2 if crash_after_claim else 1),
                    "authentic peer payload not freshly verified")
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
    if crash_after_claim:
        closed = closed_store(case)
        interrupted = case.report["interruptedStore"]
        require(closed["head"] == case.report["blockHash"]
                and closed["admission"] == case.report["recoveredAdmission"]["status"]
                and closed["bodySHA256"] == interrupted["bodySHA256"]
                and closed["proofs"]["good"]["chunkSHA256"] == interrupted["proofs"]["good"]["chunkSHA256"]
                and closed["proofs"]["good"]["status"] == case.report["recoveredVerified"]
                and closed["proofs"]["bad"] == interrupted["proofs"]["bad"], "closed recovered store mismatch")
        case.report["recoveredStore"] = closed
        case.report["crashRecoveryComplete"] = True
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
    parser.add_argument("--crash-after-claim", action="store_true",
                        help="With --recover-root and rocksdict 0.3.29, kill the owned recipient once at Verifying1")
    args = parser.parse_args()
    if args.crash_after_claim and not args.recover_root:
        parser.error("--crash-after-claim requires --recover-root")
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
                        recover(case, provider_case, args.crash_after_claim)
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
