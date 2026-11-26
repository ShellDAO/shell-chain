#!/usr/bin/env python3
"""Exercise wallet -> live validator -> durable full-QC proof -> independent peers.

Requires Python 3.11+ on Unix and a matching shell-node built with rocksdb/libp2p.
Creates disposable Dev accounts and retains all keys, chain data and checkpoints.
Proof work can take hours. Resume the same directory; never recreate its controls.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request


INITIAL = 1000 * 10**18
VALUE = 10**18


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


class Case:
    def __init__(self, binary, root, resume, algorithm=None):
        self.binary, self.root = binary, root
        self.path = root / "result.json"
        self.report = json.loads(self.path.read_text()) if resume else {"complete": False, "commands": []}
        stored_algorithm = self.report.get("validatorAlgorithm", "mldsa65")
        require(stored_algorithm in ["mldsa65", "slhdsa"], "unsupported saved validator algorithm")
        require(not resume or algorithm in [None, stored_algorithm],
                "cannot change validator algorithm when resuming a retained case")
        self.algorithm = stored_algorithm if resume else (algorithm or "mldsa65")
        if not resume:
            self.report["validatorAlgorithm"] = self.algorithm
        actual = digest(binary)
        require(self.report.get("binarySHA256", actual) == actual,
                "binary changed; inspect the retained prefix before selecting recovery")
        self.report["binarySHA256"] = actual
        self.report.pop("error", None)
        self.save()

    def save(self):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.report, indent=2) + "\n")
        temporary.replace(self.path)

    def command(self, label, args):
        row = {"label": label, "argv": [str(self.binary), *map(str, args)],
               "cwd": str(self.root), "startedAt": time.time(),
               "log": f"command-{len(self.report['commands']):03}-{label}.log"}
        self.report["commands"].append(row)
        self.save()
        log = (self.root / row["log"]).open("wb")
        child = subprocess.Popen(row["argv"], cwd=self.root, stdout=log, stderr=subprocess.STDOUT)
        row["pid"] = child.pid
        self.save()
        return child, log, row

    def finish(self, child, log, row):
        log.close()
        row.update(exitCode=child.returncode, finishedAt=time.time())
        self.save()

    def run(self, label, args, expected=0):
        child, log, row = self.command(label, args)
        try:
            child.wait(timeout=180)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            self.finish(child, log, row)
        require(child.returncode == expected, label + " failed; inspect its retained log")
        return (self.root / row["log"]).read_text()

    @contextlib.contextmanager
    def node(self, name, role="prover", production=False, admission=False, bootnode=None, budget=16):
        rpc_port, p2p_port = port(), port()
        while p2p_port == rpc_port:
            p2p_port = port()
        args = ["--datadir", name, "run", "--network", "dev", "--chain-id", "1337",
                "--db", "rocksdb", "--block-time", "2000", "--storage-profile", "full",
                "--metrics-addr", "127.0.0.1:0",
                "--node-role", role, "--consensus-engine", "wpoa", "--enable-stark-aggregation=false",
                "--rpc-addr", f"127.0.0.1:{rpc_port}", "--rpc-api", "eth,net,web3,shell,admin",
                "--p2p", "--p2p-addr", f"127.0.0.1:{p2p_port}"]
        if role == "validator-prover":
            args += ["--keystore", "validator.json", "--password-file", "password"]
        if production:
            args += ["--canonical-quorum-production", "--canonical-proof-component-budget", str(budget)]
        if admission:
            args += ["--canonical-quorum-admission"]
        if bootnode:
            args += ["--bootnode", bootnode]
        child, log, row = self.command(name + "-" + role, args)
        endpoint = f"http://127.0.0.1:{rpc_port}"
        try:
            self.wait(lambda: self.rpc(endpoint, "eth_chainId") == "0x539", child, timeout=120,
                      transient=True)
            yield endpoint, child
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            self.finish(child, log, row)
            require(child.returncode == 0, name + " did not stop cleanly; retain this prefix")

    def rpc(self, endpoint, method, params=None, reject=False):
        data = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        request = urllib.request.Request(endpoint, json.dumps(data).encode(),
                                         {"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            reply = json.load(response)
        if reject or "error" in reply:
            self.report.setdefault("rpcErrors", []).append({"request": data, "reply": reply})
            self.save()
        if reject:
            require("error" in reply, method + " unexpectedly accepted invalid input")
            return reply["error"]
        require("error" not in reply and "result" in reply, method + ": " + json.dumps(reply))
        return reply["result"]

    def wait(self, predicate, child, timeout=1800, transient=False):
        deadline = time.monotonic() + timeout
        while True:
            require(child.poll() is None, "node exited; inspect its log")
            try:
                value = predicate()
                if value:
                    return value
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                if not transient:
                    raise
            require(time.monotonic() < deadline, "node progress timed out; retain this prefix")
            time.sleep(1)

    def initialize(self):
        if self.report.get("initialized"):
            return
        require(not any((self.root / n).exists() for n in ["password", "validator.json", "genesis.json"]),
                "partial initialization present; inspect it instead of replacing controls")
        password = os.open(self.root / "password", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(password, "w") as stream:
            stream.write(secrets.token_urlsafe(32) + "\n")
        for name in ["validator", "recipient"]:
            self.run(name + "-generate", ["--password-file", "password", "key", "generate",
                     "--algorithm", self.algorithm if name == "validator" else "mldsa65",
                     "--output", name + ".json"])
            text = self.run(name + "-inspect", ["key", "inspect", name + ".json"])
            address = re.search(r"Address:\s+(0x[0-9a-f]{64})", text)
            require(address, "key inspect did not return a full-width address")
            self.report[name] = address.group(1)
        require(self.report["validator"] != self.report["recipient"], "distinct recipient required")
        genesis = {"chain_id": 1337, "chain_name": "shell-local", "network_type": "Dev",
                   "timestamp": int(time.time()), "gas_limit": 30_000_000, "extra_data": "shell-genesis",
                   "consensus": {"engine": "wpoa", "authorities": [self.report["validator"]],
                                 "authority_pubkeys": ["0x" + json.loads((self.root / "validator.json").read_text())["public_key"].removeprefix("0x")],
                                 "block_time_secs": 2, "epoch_length": 0},
                   "alloc": {self.report["validator"]: {"balance": hex(INITIAL)}}, "boot_nodes": [],
                   "block_commitment_height": 1, "native_address_context_height": 1,
                   "fee_accounting_activation_height": 1}
        (self.root / "genesis.json").write_text(json.dumps(genesis, indent=2) + "\n")
        for name in ["provider", "native", "receiver"]:
            self.run(name + "-init", ["--datadir", name, "init", "--genesis", "genesis.json",
                     "--chain-id", "1337", "--network", "dev"])
        self.report["initialized"] = True
        self.save()

    def check_scheme(self):
        kind, key_bytes, signature_bytes = {
            "mldsa65": ("MlDsa65", 1952, 3309),
            "slhdsa": ("SphincsSha2256f", 64, 49856),
        }[self.algorithm]
        key = json.loads((self.root / "validator.json").read_text())
        certificate = self.report["liveCertificate"]["certificate"]
        signature = certificate.get(self.report["validator"])
        require(len(bytes.fromhex(key["public_key"].removeprefix("0x"))) == key_bytes
                and len(certificate) == 1 and signature and signature["sig_type"] == kind
                and isinstance(signature["data"], list) and len(signature["data"]) == signature_bytes,
                "actual authority key and QC signature do not match the selected scheme")

    def snapshot(self, endpoint):
        block = self.rpc(endpoint, "eth_getBlockByNumber", ["0x1", True])
        return {"block": block, "receipts": self.rpc(endpoint, "eth_getBlockReceipts", ["0x1"]),
                "balances": [self.rpc(endpoint, "eth_getBalance", [self.report[n], "latest"])
                             for n in ["validator", "recipient"]],
                "nonces": [self.rpc(endpoint, "eth_getTransactionCount", [self.report[n], "latest"])
                           for n in ["validator", "recipient"]],
                "finalized": self.rpc(endpoint, "eth_getBlockByNumber", ["finalized", False])["hash"],
                "head": self.rpc(endpoint, "eth_blockNumber")}

    def check_state(self, snapshot):
        block, receipts = snapshot["block"], snapshot["receipts"]
        require(block and block["number"] == "0x1" and snapshot["head"] == "0x1"
                and snapshot["finalized"] == block["hash"], "expected exactly one finalized live block")
        require([int(v, 16) for v in snapshot["balances"]] == [INITIAL - VALUE, VALUE]
                and snapshot["nonces"] == ["0x1", "0x0"], "value, gas reward or nonce mismatch")
        require(len(receipts) == 2 and all(v["status"] == "0x1" for v in receipts),
                "actual transfer and gas-reward receipts required")
        require(receipts[0]["transactionHash"] == self.report["transaction"]
                and receipts[0]["to"] == self.report["recipient"]
                and receipts[0]["from"] == self.report["validator"]
                and int(receipts[0]["gasUsed"], 16) > 0, "wallet receipt identity or gas mismatch")
        fee = int(receipts[0]["gasUsed"], 16) * int(receipts[0]["effectiveGasPrice"], 16)
        reward = next(t for t in block["transactions"] if t.get("rewardKind") == "blockGasReward")
        require(fee > 0 and int(reward["value"], 16) == fee
                and reward["to"] == self.report["validator"]
                and receipts[1]["transactionHash"] == reward["hash"]
                and receipts[1]["gasUsed"] == "0x0", "effective fee/reward reconciliation failed")

    def production(self, endpoint):
        value = self.rpc(endpoint, "admin_quorumProofProduction", [self.report["blockHash"]])
        if value:
            status = value["status"]
            require(status["state"] != "failed" and (not status.get("error") or status["state"] == "paused"),
                    "quorum production failed: " + json.dumps(value))
            require(status["blockNumber"] == 1 and status["blockHash"] == self.report["blockHash"],
                    "production source identity mismatch")
            return status
        return None

    def propose(self):
        if self.report.get("proposed"):
            return
        require(not self.report.get("transaction"), "wallet already submitted; inspect its retained receipt before resuming")
        with self.node("provider", role="validator-prover", production=True, budget=2) as (endpoint, child):
            require(self.rpc(endpoint, "eth_blockNumber") == "0x0", "live validator must start at genesis")
            self.report["genesisHash"] = self.rpc(endpoint, "eth_getBlockByNumber", ["0x0", False])["hash"]
            text = self.run("wallet-send", ["tx", "send", "--to", self.report["recipient"], "--value", str(VALUE),
                            "--keystore", "validator.json", "--password-file", "password", "--rpc-url", endpoint])
            hashes = re.findall(r"^0x[0-9a-f]{64}$", text, flags=re.MULTILINE)
            require(len(hashes) == 1, "wallet did not return one transaction hash")
            self.report["transaction"] = hashes[0]
            self.save()
            receipt = self.wait(lambda: self.rpc(endpoint, "eth_getTransactionReceipt", hashes), child, timeout=120)
            self.report["blockHash"] = receipt["blockHash"]
            self.save()
            self.wait(lambda: self.rpc(endpoint, "eth_getBlockByNumber", ["finalized", False])["hash"]
                      == self.report["blockHash"], child, timeout=120)
            actual = self.snapshot(endpoint)
            self.report["liveState"] = actual
            self.report["liveCertificate"] = self.rpc(endpoint, "shell_finalityProof", [self.report["blockHash"]])
            self.report["liveSigners"] = self.rpc(endpoint, "shell_getBlockSigners", ["0x1"])
            self.save()
            self.check_state(actual)
            require(self.report["liveCertificate"].get("certificate"), "live QC was not persisted")
            self.report["malformedRejection"] = self.rpc(endpoint, "eth_sendRawTransaction", ["0x00"], reject=True)
            self.run("wallet-stale-nonce", ["tx", "send", "--to", self.report["recipient"], "--value", str(VALUE),
                     "--keystore", "validator.json", "--password-file", "password", "--rpc-url", endpoint,
                     "--nonce", "0", "--gas-limit", "21000"], expected=1)
            require(self.snapshot(endpoint) == actual, "rejected transaction changed current state")
            def paused():
                status = self.production(endpoint)
                return status if status and status["state"] == "paused" else None
            status = self.wait(paused, child)
            require(status["components"] == 2 and status["newlyProved"] == 2
                    and status["manifest"] is None, "initial bounded proof prefix mismatch")
            self.report["partialProduction"] = status
            self.report["proposed"] = True
            self.save()

    def prove(self):
        while not self.report.get("proved"):
            old = self.report.get("production", self.report["partialProduction"])
            with self.node("provider", production=True) as (endpoint, child):
                def settled():
                    status = self.production(endpoint)
                    return status if (status and status["state"] in ["paused", "complete"]
                                      and status["components"] > old["components"]) else None
                status = self.wait(settled, child)
                require(status["components"] > old["components"] and status["newlyProved"] <= 16,
                        "missing component progress or per-process budget exceeded")
                require(status["sourceHash"] == old["sourceHash"], "immutable source changed on restart")
                self.report["production"] = status
                require(self.snapshot(endpoint) == self.report["liveState"], "proof generation changed Native state")
                if status["state"] == "complete":
                    manifest = status["manifest"]
                    require(manifest and manifest["version"] == 2 and manifest["chainId"] == 1337
                            and manifest["genesisHash"] == self.report["genesisHash"]
                            and manifest["blockHash"] == self.report["blockHash"], "full-QC manifest binding mismatch")
                    upload = self.rpc(endpoint, "admin_beginCanonicalProof", [manifest])
                    self.report["proofId"] = upload["proofId"]
                    self.report["proved"] = True
                self.save()

    def verify_history(self, endpoint, child, label):
        proof_id = self.report["proofId"]
        before = self.rpc(endpoint, "admin_canonicalProofStatus", [proof_id])
        requested = self.rpc(endpoint, "admin_verifyCanonicalProof", [proof_id, True])
        self.report[label + "Request"] = {"before": before, "response": requested}
        self.save()

        def finished():
            status = self.rpc(endpoint, "admin_canonicalProofStatus", [proof_id])
            if status["state"] == "rejected":
                self.report[label + "Verification"] = status
                self.save()
                raise RuntimeError(label + " historical verification rejected: " + json.dumps(status))
            return status if (status["state"] == "verified"
                              and status["verificationAttempts"] > before["verificationAttempts"]) else None

        status = self.wait(finished, child)
        require(status["verificationAttempts"] == before["verificationAttempts"] + 1,
                label + " full verification attempt count mismatch")
        self.report[label + "Verification"] = status
        self.save()
        return status

    def peer(self):
        if self.report.get("coldVerification"):
            return
        if not self.report.get("peersComplete"):
            with self.node("provider") as (provider, producer):
                def listening():
                    value = self.rpc(provider, "admin_nodeInfo")
                    return value if value["id"] and value["listenAddr"] else None
                info = self.wait(listening, producer)
                require(info["id"] and info["listenAddr"], "provider network identity unavailable")
                multiaddr = info["listenAddr"]
                if "/p2p/" not in multiaddr:
                    multiaddr += "/p2p/" + info["id"]
                self.report["providerNodeInfo"] = info
                for name in ["native", "receiver"]:
                    with self.node(name, admission=name == "receiver", bootnode=multiaddr) as (endpoint, child):
                        def followed():
                            row = next(v for v in self.report["commands"] if v["pid"] == child.pid)
                            text = (self.root / row["log"]).read_text()
                            require("block sync import failed" not in text,
                                    name + " rejected the source block; inspect " + row["log"])
                            return self.rpc(endpoint, "eth_blockNumber") == "0x1"
                        self.wait(followed, child, timeout=1800)
                        self.wait(lambda: self.rpc(endpoint, "eth_getBlockByNumber", ["finalized", False])["hash"]
                                  == self.report["blockHash"], child)
                        actual = self.snapshot(endpoint)
                        self.check_state(actual)
                        require(actual == self.report["liveState"], name + " differs from live validator state")
                        admission = self.rpc(endpoint, "admin_canonicalProofAdmission", [self.report["blockHash"]])
                        self.report[name + "Admission"] = admission
                        if name == "native":
                            require(admission is None and self.production(endpoint) is None,
                                    "default-off Native peer generated or consumed a proof")
                        else:
                            require(admission and admission["status"]["state"] == "complete", "proof-backed admission not complete")
                            hot = self.verify_history(endpoint, child, "hot")
                            require(hot["state"] == "verified", "hot historical proof verification failed")
                            require(self.snapshot(endpoint) == actual, "historical verification wrote Native state")
                            self.report["hotVerification"] = hot
                        self.save()
                self.report["peersComplete"] = True
                self.save()
        with self.node("receiver", admission=True) as (endpoint, child):
            before = self.snapshot(endpoint)
            cold = self.verify_history(endpoint, child, "cold")
            require(cold["state"] == "verified" and self.snapshot(endpoint) == before
                    and before == self.report["liveState"], "cold proof replay changed state or receipts")
            self.report["coldVerification"] = cold
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--validator-algorithm", choices=["mldsa65", "slhdsa"],
                        help="Authority and wallet sender scheme; new cases default to mldsa65, resume keeps the saved scheme")
    parser.add_argument("--stop-after-partial", action="store_true", help="Retain the first two genuine components for later resume")
    args = parser.parse_args()
    binary, root = args.binary.resolve(strict=True), args.root.absolute()
    require(binary.is_file(), "matching shell-node binary required")
    require(not root.is_symlink() and root.exists() == args.resume, "new directory required, or use --resume")
    if not args.resume:
        root.mkdir(mode=0o700)
    require(not any(p.is_symlink() for p in root.rglob("*")), "case contains symbolic links")
    with (root / "run.lock").open("a+b") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        case = Case(binary, root, args.resume, args.validator_algorithm)
        try:
            if not case.report["complete"]:
                case.initialize()
                case.propose()
                case.check_scheme()
                if args.stop_after_partial:
                    print(json.dumps({"liveWalletPartial": True, "block": case.report["blockHash"], "components": 2}))
                    return
                case.prove()
                case.peer()
                case.report["complete"] = True
                case.save()
            case.check_scheme()
            print(json.dumps({"liveWalletQuorumComplete": True, "block": case.report["blockHash"],
                              "components": case.report["production"]["components"],
                              "proofId": case.report["proofId"]}))
        except BaseException as error:
            case.report["error"] = str(error)
            case.save()
            raise


if __name__ == "__main__":
    main()
