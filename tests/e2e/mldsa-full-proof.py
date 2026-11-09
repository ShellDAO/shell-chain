#!/usr/bin/env python3
"""Full MLDSA65 proposer and sender AIR: durable production, peer intake and replay.

Python 3, stable Rust and the repository RocksDB prerequisites are required.
This expensive public-certificate test creates fresh test keys in memory only.
Keep its output directory: run resumes checkpoints; verify never regenerates them.
Every child has a durable argv/PID/log/exit receipt. Any failed assertion exits nonzero.
"""
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

mode, raw_fixture, raw_output = sys.argv[1:]
assert mode in ("dilithium-run", "dilithium-proposer", "dilithium-verify", "run", "verify", "consecutive", "batch", "first-use", "wide", "mixed", "eight-keys", "sixteen-keys", "mixed-first-use", "rotation", "rotation-raw")
fixture, out = map(lambda p: Path(p).resolve(), (raw_fixture, raw_output))

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)

def run(label, args, expected=0):
    receipts = out / "commands"
    receipts.mkdir(exist_ok=True)
    path = receipts / (label + ".json")
    if path.exists():
        previous = json.loads(path.read_text())
        if "exit_code" not in previous:
            try:
                os.kill(previous["pid"], 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError(f"{label} still owns PID {previous['pid']}; inspect its log")
        # Preserve incomplete/failed run receipts and always use a new attempt.
        index = 2
        while path.exists():
            path = receipts / f"{label}-{index}.json"
            index += 1
    log = path.with_suffix(".log")
    record = {"argv": list(map(str, args)), "cwd": str(Path.cwd()), "started_at": now(), "log": str(log)}
    with log.open("w") as stream:
        child = subprocess.Popen(record["argv"], stdout=stream, stderr=subprocess.STDOUT)
        record["pid"] = child.pid
        save(path, record)
        record["exit_code"] = child.wait()
    record["finished_at"] = now()
    save(path, record)
    text = log.read_text()
    assert record["exit_code"] == expected, f"{label}: {record['exit_code']} != {expected}; see {log}"
    return text

def snapshot(label):
    return json.loads(run(label, [fixture, "full-snapshot", out]))

def history_verify():
    run("full-history-verify", [fixture, "full-history-verify", out])

if mode in ("dilithium-run", "dilithium-proposer", "dilithium-verify"):
    out.mkdir(exist_ok=True)
    network = out / "network-dilithium"
    if mode == "dilithium-verify":
        run("dilithium-cold-verify", [fixture, "dilithium-verify", out])
        sys.exit(0)
    raw_proposer = mode == "dilithium-proposer"
    if not (out / "actors.json").exists():
        prepare = "prepare-dilithium-proposer" if raw_proposer else "prepare-dilithium"
        run(prepare, [fixture, prepare, out])
    actors = json.loads((out / "actors.json").read_text())
    assert actors["sender_algorithm"] == ("MlDsa65" if raw_proposer else "Dilithium3") and actors["proposer_algorithm"] == ("Dilithium3" if raw_proposer else "MlDsa65"), "retained algorithm roles differ; choose a new output directory"
    assert (out / "later-control.json").exists(), "partial preparation retained; inspect receipts"
    original = json.loads((out / "capture-original.json").read_text())
    if not original["supported"] and not (out / "capture-recovered.json").exists():
        run("dilithium-probe", [fixture, "dilithium-probe", out])
    if not (network / "paused.json").exists():
        run("dilithium-pause", [fixture, "dilithium-pause", out])
        save(out / "dilithium-paused-snapshot.json", json.loads(run("dilithium-paused-snapshot", [fixture, "dilithium-snapshot", out])))
    assert (out / "dilithium-paused-snapshot.json").exists(), "unrecorded pause retained; inspect receipts"
    if not (network / "complete.json").exists():
        run("dilithium-resume", [fixture, "dilithium-resume", out])
    after = json.loads(run("dilithium-complete-snapshot", [fixture, "dilithium-snapshot", out]))
    paused = json.loads((out / "dilithium-paused-snapshot.json").read_text())
    assert paused["native_digest"] == after["native_digest"] and after["physical_checkpoint_bytes"] <= 256 * 1024 * 1024
    indexed = {row["key"]: row for row in after["rows"]}
    for row in paused["rows"]:
        key = bytes.fromhex(row["key"])
        if b"production/component/" in key or b"production/source" in key or b"/source/" in key:
            assert indexed[row["key"]] == row, "original checkpoint changed"
    if not (network / "verified.json").exists():
        run("dilithium-verify", [fixture, "dilithium-verify", out])
    if not (network / "history-verified.json").exists():
        run("dilithium-history", [fixture, "dilithium-history", out])
    if not (network / "refusals.json").exists():
        run("dilithium-refusal", [fixture, "dilithium-refusal", out])
    run("dilithium-history-cold", [fixture, "dilithium-verify", out])
    run("dilithium-history-cold-again", [fixture, "dilithium-verify", out])
    complete = json.loads((network / "complete.json").read_text())
    key = "genuine_dilithium_proposer_primary_sender_full_proof_admitted" if raw_proposer else "genuine_dilithium_sender_primary_proposer_full_proof_admitted"
    assert complete[key] and complete["height"] == complete["finalized"] == 1
    assert complete["production"]["state"] == "complete" and complete["production"]["components"] > 0
    assert complete["admission"]["nativeCanonical"] and complete["admission"]["status"]["state"] == "complete"
    for name, count in (("control.json", 1), ("later-control.json", 2)):
        control = json.loads((out / name).read_text())
        sender, recipient, proposer = control["accounts"]
        assert sender["nonce"] == count and int(sender["balance"], 16) == 1_000_000 - count * 42_001
        assert int(recipient["balance"], 16) == count and int(proposer["balance"], 16) == count * 42_000
        assert [v["gas_used"] for v in control["receipts"]] == [21_000, 0] and all(v["status"] == 1 for v in control["receipts"])
    for path in network.glob("history-verified*.json"):
        value = json.loads(path.read_text())
        assert value["all_kv_unchanged"] and value["current_height"] == 2 and value["ordinary_successor_not_proof_admitted"]
    rollback = json.loads((out / "native-rollback.json").read_text())
    assert rollback["native_crypto_control_not_proof_admission"] and rollback["all_kv_unchanged"]
    refusals = json.loads((network / "refusals.json").read_text())
    assert refusals["genuine_primary_certificates"] and len(refusals["cases"]) == 4
    assert all(v["all_kv_unchanged"] and v["original_proof_unchanged"] and v["new_proofs_generated"] == 0 for v in refusals["cases"])
    result = {key: True, "legacy_proposer": raw_proposer,
              "historical_replay_after_native_successor_no_writes": True,
              "foreign_profile_and_genuine_certificate_refusals": 4,
              "physical_checkpoint_bytes": after["physical_checkpoint_bytes"],
              "components": complete["production"]["components"], "finished_at": now()}
    save(out / "dilithium-result.json", result)
    print(json.dumps(result))
    sys.exit(0)

if mode == "verify" and (out / "network-rotation/complete.json").exists():
    run("rotation-cold-verify", [fixture, "rotation-verify", out])
    sys.exit(0)
if mode in ("rotation", "rotation-raw"):
    active = mode == "rotation"
    expected_activation = 1 if active else None
    out.mkdir(exist_ok=True)
    if not (out / "rotation.json").exists():
        prepare = "prepare-rotation" if active else "prepare-rotation-raw"
        run(prepare, [fixture, prepare, out])
    info = json.loads((out / "rotation.json").read_text())
    assert info["activation_height"] == expected_activation, "retained rotation activation differs; preserve this output and choose a new directory"
    network = out / "network-rotation"
    if not (network / "paused.json").exists():
        run("rotation-pause", [fixture, "rotation-pause", out])
        save(out / "rotation-paused-snapshot.json", json.loads(run("rotation-paused-snapshot", [fixture, "rotation-snapshot", out])))
    if not (network / "complete.json").exists():
        run("rotation-resume", [fixture, "rotation-resume", out])
    after = json.loads(run("rotation-complete-snapshot", [fixture, "rotation-snapshot", out]))
    paused = json.loads((out / "rotation-paused-snapshot.json").read_text())
    assert paused["native_digest"] == after["native_digest"] and after["physical_checkpoint_bytes"] <= 256 * 1024 * 1024
    if not (network / "verified.json").exists():
        run("rotation-verify", [fixture, "rotation-verify", out])
    if not (network / "history-verified.json").exists():
        run("rotation-history", [fixture, "rotation-history", out])
    if not (network / "old-key-refused.json").exists():
        run("rotation-old-key-refusal", [fixture, "rotation-old-key-refusal", out])
    run("rotation-history-cold", [fixture, "rotation-verify", out])
    run("rotation-history-cold-again", [fixture, "rotation-verify", out])
    complete = json.loads((network / "complete.json").read_text())
    assert complete["both_full_proof_admitted"] and complete["raw_then_tagged_proof_binding"] == active and complete["height"] == complete["finalized"] == 2
    assert complete.get("registered_key_algorithm_height", info["activation_height"]) == expected_activation
    assert all(row["state"] == "complete" and row["components"] > 0 for row in complete["production"])
    assert all(row["nativeCanonical"] and row["status"]["state"] == "complete" for row in complete["admission"])
    rollback = json.loads((out / "rotation-native-rollback.json").read_text())
    assert rollback["native_crypto_control_not_proof_admission"] and rollback["all_kv_unchanged"] and rollback["old_key_and_commitment_preserved"]
    assert all(row["all_kv_unchanged"] for row in json.loads((out / "native-refusals.json").read_text()))
    for path in network.glob("history-verified*.json"):
        value = json.loads(path.read_text())
        assert value["all_kv_unchanged"] and value["current_height"] == 4 and value["ordinary_advance_not_proof_admitted"]
    refusal = json.loads((network / "old-key-refused.json").read_text())
    assert refusal["genuine_old_key_certificate"] and refusal["all_kv_unchanged"] and refusal["original_proof_unchanged"] and refusal["new_proofs_generated"] == 0
    save(out / "rotation-result.json", {"both_full_proof_admitted": True, "finalized": 2, "stable_address": complete["stable_address"], "physical_checkpoint_bytes": after["physical_checkpoint_bytes"], "raw_then_tagged_binding": active, "registered_key_algorithm_height": expected_activation, "changed_current_key_history_read_only": True, "finished_at": now()})
    sys.exit(0)

if mode == "verify" and (out / "network-wide/complete.json").exists():
    historical = (out / "network-wide/history-verified.json").exists()
    run("wide-cold-verify", [fixture, "wide-history-verify" if historical else "wide-verify", out])
    sys.exit(0)
if mode == "verify" and (out / "network-batch/complete.json").exists():
    historical = (out / "network-batch/history-verified.json").exists()
    run("batch-cold-verify", [fixture, "batch-history-verify" if historical else "batch-verify", out])
    sys.exit(0)
if mode in ("batch", "first-use", "wide", "mixed", "eight-keys", "sixteen-keys", "mixed-first-use"):
    wide = mode in ("wide", "mixed", "eight-keys", "sixteen-keys", "mixed-first-use")
    first_use = mode in ("first-use", "mixed-first-use")
    unbound = 8 if mode == "mixed-first-use" else 1 if first_use else 0
    label = mode
    registered = 16 if mode in ("sixteen-keys", "mixed-first-use") else 8 if mode == "eight-keys" else 2 if mode == "mixed" else 1
    unique_components = 982 if registered == 16 else 433 + 40 * (registered - 1) if wide else 179
    count = 16 if wide else 2
    shared_inputs = 40 * (count - registered) if wide else 41 if first_use else 40
    funding = 2_000_000 if wide else 1_000_000
    out.mkdir(exist_ok=True)
    if not (out / "control.json").exists():
        run("prepare-" + label, [fixture, "prepare-" + label, out])
    assert (out / "batch-fixture.json").exists(), "partial batch preparation retained; inspect receipts"
    assert json.loads((out / "control.json").read_text())["raw_fresh_sender_count"] == registered, "retained fixture has a different sender profile"
    if first_use:
        assert json.loads((out / "control.json").read_text())["first_use_parent_unregistered"]
        assert json.loads((out / "control.json").read_text()).get("unbound_sender_count", unbound) == unbound
        refusals = json.loads((out / "first-use-native-refusals.json").read_text())
        assert refusals["real_signatures"] and not refusals["private_keys_persisted"]
        assert {row["case"] for row in refusals["cases"]} == {"reference-before-registration", "wrong-derived-address", "insufficient-funds"}
        assert all(row["all_kv_unchanged"] and not row["key_registered"] for row in refusals["cases"])
        rollback = json.loads((out / "first-use-native-root-rollback.json").read_text())
        assert rollback["native_crypto_control_not_proof_admission"] and rollback["all_kv_unchanged"] and not rollback["key_registered"]
        assert rollback["transactions_executed_before_root_refusal"] == count
    for name, nonce in (("control.json", count), ("later-control.json", 2 * count)):
        control = json.loads((out / name).read_text())
        senders = control["accounts"][:registered]
        recipient, proposer = control["accounts"][registered:]
        assert len({row["address"] for row in control["accounts"]}) == registered + 2
        assert all(sender["nonce"] == nonce // registered and int(sender["balance"], 16) == funding - nonce // registered * 42_001 for sender in senders)
        assert int(recipient["balance"], 16) == nonce and int(proposer["balance"], 16) == nonce * 42_000
        receipts = control["receipts"]
        assert len(receipts) == count + 1 and all(receipt["status"] == 1 for receipt in receipts)
        assert [receipt["gas_used"] for receipt in receipts] == [21_000] * count + [0]
        assert [receipt["cumulative_gas_used"] for receipt in receipts] == [21_000 * (i + 1) for i in range(count)] + [21_000 * count]
    network = out / ("network-wide" if wide else "network-batch")
    if not (network / "paused.json").exists():
        run((label + "-pause"), [fixture, (label + "-pause"), out])
        save(out / (label + "-paused-snapshot.json"), json.loads(run((label + "-paused-snapshot"), [fixture, (label + "-snapshot"), out])))
    assert (out / (label + "-paused-snapshot.json")).exists(), "unrecorded batch pause retained"
    if first_use:
        initial = json.loads((network / "initial.json").read_text())
        assert initial["first_use_parent_unregistered"] and initial["initial_registered_sender_keys"] == registered - unbound
    if not (network / "complete.json").exists():
        run((label + "-resume"), [fixture, (label + "-resume"), out])
    after = json.loads(run((label + "-complete-snapshot"), [fixture, (label + "-snapshot"), out]))
    paused = json.loads((out / (label + "-paused-snapshot.json")).read_text())
    assert paused["native_digest"] == after["native_digest"], "batch proving changed Byzantine provider native data"
    indexed = {row["key"]: row for row in after["rows"]}
    for row in paused["rows"]:
        key = bytes.fromhex(row["key"])
        if b"production/component/" in key or b"production/source" in key or b"/source/" in key:
            assert indexed[row["key"]] == row, "retained batch certificate/source changed"
    attempts = []
    for phase in (label + "-pause", label + "-resume"):
        for path in (out / "commands").glob(phase + "*.log"):
            receipt = json.loads(path.with_suffix(".json").read_text())
            assert "exit_code" in receipt, "unfinished producer attempt retained"
            attempts.append((receipt["started_at"], path, receipt))
    attempts.sort(key=lambda row: row[0])
    stable = re.compile(r"^(sender-[0-9]+|proposer)-(key|key-hash|tagged-key|tr|matrix-(?:[0-5]-[0-4]|(?:sampler|sponge|keccak)-[0-9]+)|t1-[0-5])$")
    shared = set()
    failed_shared_repetitions = []
    for _, path, receipt in attempts:
        for name in re.findall(r"^Proving (.+)$", path.read_text(), re.M):
            if not stable.fullmatch(name):
                continue
            if name in shared:
                assert receipt["exit_code"] != 0, "completed attempt regenerated retained shared inputs"
                failed_shared_repetitions.append({"input": name, "attempt": path.name, "exit_code": receipt["exit_code"]})
            shared.add(name)
    fresh_senders = {name.removesuffix("-key") for name in shared if re.fullmatch(r"sender-[0-9]+-key", name)}
    matrix_parts = sum("-matrix-" in name for name in shared)
    expected_shared = 152 + matrix_parts + unbound if registered == 16 else 78 if first_use else 77 + 39 * (registered - 1)
    assert len(shared) == expected_shared and len(fresh_senders) == registered, "shared batch key input coverage differs"
    if registered == 16:
        assert matrix_parts >= 27 * 17, "shared full-matrix parts missing"
        assert not any(re.search(r"-matrix-[0-5]-[0-4]$", name) for name in shared), "shared matrix used standalone certificates"
    else:
        assert matrix_parts == 30 * (registered + 1), "fresh sender/proposer matrix profile mismatch"
    completed = json.loads((network / "complete.json").read_text())
    assert completed["production1"]["reused"] >= shared_inputs and completed["production2"]["reused"] >= shared_inputs + expected_shared, "cross-position inputs not reverified"
    if first_use:
        unique_components = completed["production1"]["components"]
        assert unique_components > 0 and completed["production2"]["components"] > 0
        assert completed["unbound_first_use_registration_verified"]
        assert all(row["profiles"].count(2) == unbound * count // registered and row["profiles"].count(1) == count - unbound * count // registered for row in completed["sender_profiles"])
    elif registered == 16:
        unique_components = completed["production1"]["components"]
        assert unique_components >= 982 and completed["production2"]["components"] == unique_components
    if not (network / "verified.json").exists():
        run((label + "-verify"), [fixture, (label + "-verify"), out])
    if not (network / "history-verified.json").exists():
        run((label + "-history"), [fixture, (label + "-history"), out])
    if (registered > 1 or first_use) and not (network / "cross-key-refused.json").exists():
        run("mixed-key-swap", [fixture, "mixed-key-swap", out])
    if first_use and not (network / "address-refused.json").exists():
        run("unbound-address-refusal", [fixture, "unbound-address-refusal", out])
    if mode in ("eight-keys", "sixteen-keys", "mixed-first-use") and not (network / "aggregate-refused.json").exists():
        run("matrix-aggregate-refusal", [fixture, "matrix-aggregate-refusal", out])
    run((label + "-history-cold"), [fixture, (label + "-history-verify"), out])
    run((label + "-history-cold-again"), [fixture, (label + "-history-verify"), out])
    if first_use and not wide and not (out / "compact-first-use/complete.json").exists():
        run("first-use-compact-roundtrip", [fixture, "compact-roundtrip", out, out / "compact-first-use"])
    result = {"two_ordered_transactions_proof_admitted": True,
              "signed_wrong_root_child_executed_and_atomically_refused": True,
              "bad_source_is_byzantine_storage_only": True,
              "components_per_full_graph": unique_components if registered == 16 or first_use else 1033 if wide else 179, "unique_checkpoint_components": unique_components, "checkpoint_components_per_graph": [completed["production1"]["components"], completed["production2"]["components"]], "transactions_per_block": count, "registered_sender_keys": registered, "unbound_sender_keys": unbound, "initial_bound_sender_keys": registered - unbound,
              "unique_fresh_matrix_certificates": matrix_parts if registered == 16 else 30 * (registered + 1),
              "retained_failed_attempt_shared_repetitions": failed_shared_repetitions,
              "no_completed_attempt_regenerates_retained_shared_inputs": True,
              "physical_checkpoint_bytes": after["physical_checkpoint_bytes"],
              "reused1": completed["production1"]["reused"], "reused2": completed["production2"]["reused"],
              "native_control_and_cold_historic_replay_match": True, "finished_at": now()}
    if registered > 1 or first_use:
        refusal = json.loads((network / "cross-key-refused.json").read_text())
        assert refusal["all_kv_unchanged"] and refusal["original_proof_unchanged"] and refusal["new_proofs_generated"] == 0
        result["valid_other_registered_key_certificate_refused"] = True
    if first_use:
        refusal = json.loads((network / "address-refused.json").read_text())
        assert refusal["genuine_raw_key_hash_cannot_authorize_unbound_address"] and refusal["all_kv_unchanged"] and refusal["original_proof_unchanged"] and refusal["new_proofs_generated"] == 0
        result["first_use_parent_unregistered"] = True
        result["wrong_address_certificate_refused"] = True
    if mode in ("eight-keys", "sixteen-keys", "mixed-first-use"):
        refusal = json.loads((network / "aggregate-refused.json").read_text())
        assert refusal["changed_intermediate_lane_with_genuine_aggregate"] and refusal["all_kv_unchanged"] and refusal["original_proof_unchanged"] and refusal["new_proofs_generated"] == 0
        result["altered_aggregate_with_correct_outer_hash_refused"] = True
    if wide:
        result["sixteen_ordered_transactions_proof_admitted"] = result.pop("two_ordered_transactions_proof_admitted")
    save(out / (label + "-result.json"), result)
    print(json.dumps(result))
    sys.exit(0)
if mode == "verify":
    assert (out / "network-full/complete.json").exists(), "full peer import incomplete"
    if (out / "network-consecutive/complete.json").exists():
        run("consecutive-verify", [fixture, "consecutive-verify", out])
    elif (out / "network-full/history-verified.json").exists():
        history_verify()
    else:
        run("full-verify", [fixture, "full-verify", out])
    sys.exit(0)
if mode == "consecutive":
    assert (out / "full-result.json").exists(), "complete run output required"
    if not (out / "consecutive-donor-snapshot.json").exists():
        save(out / "consecutive-donor-snapshot.json", snapshot("consecutive-donor-snapshot"))
    network = out / "network-consecutive"
    if not (network / "paused.json").exists():
        run("consecutive-pause", [fixture, "consecutive-pause", out])
        save(out / "consecutive-paused-snapshot.json", json.loads(run("consecutive-paused-snapshot", [fixture, "consecutive-snapshot", out])))
    assert (out / "consecutive-paused-snapshot.json").exists(), "unrecorded consecutive pause retained"
    if not (network / "complete.json").exists():
        run("consecutive-resume", [fixture, "consecutive-resume", out])
    after = json.loads(run("consecutive-complete-snapshot", [fixture, "consecutive-snapshot", out]))
    paused = json.loads((out / "consecutive-paused-snapshot.json").read_text())
    assert paused["native_digest"] == after["native_digest"], "consecutive proving changed native provider"
    indexed = {row["key"]: row for row in after["rows"]}
    donor = json.loads((out / "consecutive-donor-snapshot.json").read_text())
    for row in donor["rows"]:
        if bytes.fromhex(row["key"]) not in (b"local/canonical-production/v1/bytes", b"local/canonical-production/v1/jobs"):
            assert indexed[row["key"]] == row, "original donor certificate/source changed"
    logs = "\n".join(path.read_text() for label in ("consecutive-pause", "consecutive-resume") for path in (out / "commands").glob(label + "*.log"))
    generated = re.findall(r"^Proving (.+)$", logs, re.M)
    borrowed = re.findall(r"^Borrowed and reverified (.+)$", logs, re.M)
    common = re.compile(r"^(sender-0|proposer)-(key|key-hash|tagged-key|tr|matrix-(?:[0-5]-[0-4]|(?:sampler|sponge|keccak)-[0-9]+)|t1-[0-5])$")
    assert len(generated) == len(set(generated)) == 41 and not any(common.fullmatch(name) for name in generated), "common math was regenerated"
    assert len(borrowed) == len(set(borrowed)) == 77 and all(common.fullmatch(name) for name in borrowed), "common certificates not reverified"
    run("consecutive-verify", [fixture, "consecutive-verify", out])
    run("consecutive-verify-cold", [fixture, "consecutive-verify", out])
    if not (out / "network-consecutive-bad/refused.json").exists():
        run("consecutive-bad-reference", [fixture, "consecutive-bad-reference", out])
    save(out / "consecutive-result.json", {"both_full_targets_proof_admitted": True, "common_components_reverified_not_regenerated": 77,
         "new_input_components_proved": 41, "physical_checkpoint_bytes": after["physical_checkpoint_bytes"],
         "original_donor_immutable": True, "cold_two_target_replays_no_writes": True,
         "corrupt_reference_production_refused": True, "finished_at": now()})
    sys.exit(0)
out.mkdir(exist_ok=True)
if not (out / "control.json").exists():
    run("prepare-full", [fixture, "prepare-full", out])
assert (out / "later-control.json").exists(), "partial native preparation retained; inspect receipts"
if not (out / "network-full/paused.json").exists():
    run("full-pause", [fixture, "full-pause", out])
    save(out / "full-paused-snapshot.json", snapshot("full-paused-snapshot"))
assert (out / "full-paused-snapshot.json").exists(), "unrecorded full pause retained"
if not (out / "network-full/complete.json").exists():
    run("full-resume", [fixture, "full-resume", out])
paused = json.loads((out / "full-paused-snapshot.json").read_text())
after = snapshot("full-complete-snapshot")
assert paused["native_digest"] == after["native_digest"], "proving changed native source state"
indexed = {row["key"]: row for row in after["rows"]}
for row in paused["rows"]:
    key = bytes.fromhex(row["key"])
    if b"production/component/" in key or b"production/source" in key or b"/source/" in key:
        assert indexed[row["key"]] == row, "retained full certificate/source changed"
if not (out / "network-full/verified.json").exists():
    run("full-verify", [fixture, "full-verify", out])
if not (out / "network-full/history-verified.json").exists():
    run("full-history", [fixture, "full-history", out])
history_verify()
if not (out / "network-full-bad/envelope-refused.json").exists():
    run("full-bad-proposer", [fixture, "full-bad-proposer", out])
result = {"real_node_run": True, "fresh_MLDSA65_sender_and_proposer": True,
          "native_production_captured_v2": True, "shutdown_checkpoint_reverified": True,
          "complete_components": 118, "native_peer_import_consumed_proposer_AIR": True,
          "native_controls_match": True, "cold_replay_and_changed_current_state_no_writes": True,
          "bad_proposer_AIR_and_invalid_envelopes_refused": True,
          "proof_bytes": (out / "job/proof.json").stat().st_size, "finished_at": now()}
path = out / "full-result.json"
assert not path.exists(), "full result exists; use verify"
save(path, result)
print(json.dumps(result))
