# Prover Guide

Shell-Chain supports asynchronous STARK proof generation. Blocks are produced
and broadcast immediately (native Dilithium3 signature verification), and a
`ProofAmendment` is attached later by a prover node. This lets validators stay
responsive without waiting for expensive proof generation.

---

## Table of Contents

- [Node Roles](#node-roles)
- [How Proving Works](#how-proving-works)
- [ProverRegistry](#proverregistry)
- [Running a Prover Node](#running-a-prover-node)
- [Running a ValidatorProver Node](#running-a-validatorprover-node)
- [Configuration Reference](#configuration-reference)
- [ProofAmendment Lifecycle](#proofamendment-lifecycle)
- [Monitoring](#monitoring)
- [Proof Challenge Mechanism](#proof-challenge-mechanism)

---

## Node Roles

Shell-Chain defines three operational roles:

| Role | CLI value | Block production | Generates proofs | Description |
|------|-----------|-----------------|-----------------|-------------|
| **Validator** | `validator` *(default)* | ✅ | ❌ | Standard authority node. Signs and proposes blocks. Does not run the prover. |
| **ValidatorProver** | `validator-prover` | ✅ | ✅ (idle slots) | Authority node that also runs the prover service during idle (non-proposing) slots. Useful for small networks where each validator can contribute proof work. |
| **Prover** | `prover` | ❌ | ✅ (full time) | Standalone prover — syncs the chain, generates proofs for every incoming block, broadcasts `ProofAmendment` via P2P. No block-signing key required. |

Set the role via TOML or CLI:

```toml
# config.toml
[node]
node_role = "prover"
```

```bash
shell-node run --node-role prover --config config.toml
```

### L2StarkMode

The prover's contribution to proof availability is controlled by `L2StarkMode`:

| Mode | CLI value | Behaviour |
|------|-----------|-----------|
| `Disabled` | `"disabled"` | No STARK proofs generated or forwarded |
| `Scaffold` | `"scaffold"` | Proofs generated but not actively circulated; development/testing mode |
| `Active` | `"active"` | Full proof pipeline: generate → store → broadcast `ProofAmendment` |

```toml
[prover]
l2_stark_mode = "active"
```

---

## How Proving Works

```
Block N sealed by validator
        │
        ▼
Broadcast to network (contains Dilithium3 sigs in WitnessBundle)
        │
        ├──► Peers: verify natively with TxWitness signatures (instant)
        │
        └──► Prover node receives block
                  │
                  ▼
            prove_sig_batch(entries) → SigBatchProof   ← Winterfell STARK
                  │
                  ▼
            Wrap in ProofAmendment { block_hash, block_number, proof, prover, prover_sig }
                  │
                  ▼
            P2P broadcast → peers store at pa/<block_hash>
                  │
                  ▼
            (if proof_replacement_grace == 0)  delete w/<block_hash>
                      ← WitnessBundle freed (~4 KB/tx saved)
```

---

## ProverRegistry

The native ProverRegistry stores governance-approved proof signing identities in
canonical chain state, separately from validator membership. Registration grants
no block-production or consensus-voting rights.

**Version and activation:** this interface is an unreleased source feature. It
requires a node build containing `shell_proposeRegisterProver` and an explicitly
configured `prover_registry_height`. The default is disabled. Existing databases
accept only a future activation height, and a saved schedule cannot be changed.
All peers must use the same schedule; snapshots must match trusted configuration.
Do not set height zero on an existing network. Before activation, historical
proof admission and settlement rules remain unchanged. At and after activation,
proof admission and settlement require a registered prover, including proofs
from `validator-prover` nodes.

### Registering a prover

First generate the proof signing key as shown below. Submit only its public key
and algorithm ID to a funded validator's authenticated governance RPC. Each
validator votes through its own node; registration completes when votes represent
strictly more than half of the current Registry weight. Repeating a vote does not
add weight. No prior transaction from the prover account is required.

For the Dilithium3 key generated in this guide (`algorithm = 0`), with `jq` and
`curl` installed:

```bash
PROVER_PUBLIC_KEY=$(jq -r '.public_key' /data/prover-keystore.json)
PROVER_ADDRESS=$(jq -r '.address' /data/prover-keystore.json)
VALIDATOR_RPC=http://127.0.0.1:8545
REQUEST=$(jq -nc --arg key "$PROVER_PUBLIC_KEY" \
  '{jsonrpc:"2.0",id:1,method:"shell_proposeRegisterProver",params:[$key,0]}')
curl -sS -H 'Content-Type: application/json' --data "$REQUEST" "$VALIDATOR_RPC"
```

The result is a transaction hash. Query `eth_getTransactionReceipt` with that
hash and require `status: "0x1"`. A successful vote receipt alone does not prove
quorum: query the record and wait for its `registered_at` block to be finalized
(`eth_getBlockByNumber` with `["finalized", false]`) before starting the prover.

```bash
REQUEST=$(jq -nc --arg address "$PROVER_ADDRESS" \
  '{jsonrpc:"2.0",id:2,method:"shell_getRegisteredProver",params:[$address]}')
curl -sS -H 'Content-Type: application/json' --data "$REQUEST" "$VALIDATOR_RPC"
```

The query returns `null` until registration is committed. Match `pubkey` and
`algorithm` to your key and check that `shell_getValidators` is unchanged.
ML-DSA-65 uses algorithm ID `1`; SPHINCS+-SHA2-256f uses `2`. Addresses are derived
as `blake3(algo_id || pubkey)`, rendered as `0x` plus 64 lowercase hex characters.
Malformed keys, unsupported algorithms, non-validator callers, and duplicate
registrations are rejected. `shell_proposeAddValidator` changes consensus
membership and is not the prover-registration operation.

When the validator RPC listener is non-loopback, the node must be configured
with `--rpc-api-key`; add `Authorization: Bearer <key>` to the requests above.
Keep the prover's encrypted key and password on the prover machine.

### ProverRecord fields

| Field | Description |
|-------|-------------|
| `address` | Prover's full 32-byte address |
| `pubkey` | Public key bound to this proof signing identity |
| `algorithm` | Signature algorithm ID: 0, 1, or 2 |
| `registered_at` | Block height where governance reached quorum |
| `proofs_submitted` | Successfully executed proof settlements since registration |
| `last_proof_block` | Highest source block covered by those settlements |

Receiving or storing a proof does not increment the count. Settlement updates
share the block's state root, roll back with rejected blocks or failed execution,
and persist through restart and snapshot recovery. Import and replay use the
registry state of the block being executed.

---

## Running a Prover Node

A prover node does not need a validator identity. It uses a separate prover
keystore to sign proof amendments and does not propose or vote on blocks. It needs:

1. A PQ key for signing `ProofAmendment` messages
2. Registration in `ProverRegistry`
3. Access to a synced peer (or full P2P participation)

### Step 1: Generate a prover key

```bash
shell-node key generate --algorithm dilithium3 --output /data/prover-keystore.json
# Enter passphrase when prompted
```

### Step 2: Config

```toml
# prover.toml
[node]
datadir = "/data/prover"
chain_id = 31337
node_role = "prover"
keystore = "/data/prover-keystore.json"  # proof signing only; not a validator key

[rpc]
listen_addr = "127.0.0.1:8545"  # optional — prover nodes rarely need RPC

[p2p]
enabled = true
listen_addr = "0.0.0.0:30303"
bootnodes = ["/ip4/VALIDATOR_IP/tcp/30303/p2p/QmVALIDATOR..."]

[consensus]
enable_stark_aggregation = true

[prover]
max_concurrent_proofs = 2         # default 1; increase for multi-core machines
proving_priority = "sequential"   # "sequential" or "latest-first"

[metrics]
enabled = true
listen_addr = "0.0.0.0:9090"
```

### Step 3: Start

```bash
shell-node run --config prover.toml
```

Enter the passphrase for the prover keystore generated in Step 1. The
`[node].keystore` setting selects the proof-signing identity; generating a key
alone does not configure it. If omitted, the node creates or loads its development
identity instead, which has a different address from the generated prover key.
Keep `node_role = "prover"` so loading the key does not enable block production.

To check key selection and restart with fresh local accounts, build `shell-node`
and run `python3 tests/e2e/prover-config.py --prover-key` from the node repository.
This check compares the omitted-key baseline with the configured identity;
registration and complete proof generation are separate acceptance steps.

---

## Running a ValidatorProver Node

A `validator-prover` node runs both roles. The prover service starts
automatically during slots where this node is not the block proposer.

```toml
[node]
node_role = "validator-prover"
keystore = "/data/keystore.json"

[consensus]
enable_stark_aggregation = true

[prover]
max_concurrent_proofs = 1       # conservative on validator hardware
proving_priority = "sequential"
```

> **Tip:** On dedicated proving hardware, set `max_concurrent_proofs` to the
> number of physical CPU cores. The Winterfell STARK prover is CPU-bound and
> benefits from parallelism.

---

## Configuration Reference

```toml
[node]
node_role = "validator"       # "validator" | "validator-prover" | "prover"

[consensus]
enable_stark_aggregation = false  # explicitly set true to prepare STARK proof inputs

[prover]
max_concurrent_proofs = 1         # parallel proof jobs
proving_priority = "sequential"   # "sequential" (oldest first) | "latest-first"

[pruning]
proof_replacement_grace = 0       # blocks to keep WitnessBundle after proof arrival
                                  # 0 = delete immediately (default, recommended)
```

### Checking aggregation configuration

On source versions that support `consensus.enable_stark_aggregation` in TOML,
the CLI takes precedence. A bare `--enable-stark-aggregation` enables input
collection; `--enable-stark-aggregation=false` overrides a configured enablement.
Omitting both keeps aggregation disabled.

Run the configuration acceptance with Python 3 after building the node with
RocksDB support (enabled by default):

```bash
cargo build -p shell-cli
python3 tests/e2e/prover-config.py
```

It creates isolated development nodes and fresh keys, submits real transfers,
checks block commitments for enabled/disabled and CLI override cases, and
verifies the stored blocks after restarting RocksDB. A single transaction stays
below the 512-entry L1 proof threshold: this checks input creation and persistence,
not completed proof generation, concurrent proving, or public-network activation.

### max_concurrent_proofs

Set a positive integer (default `1`). Zero, negative and non-integer values are
rejected at configuration load. On builds containing the concurrent prover
implementation, this bounds active CPU proof jobs and completed jobs awaiting
ordered delivery. A later range may finish first, but persistence and event-loop
handoff remain in canonical source order. Source reservations stay active until
handoff is acknowledged. Graceful shutdown stops admission and drains active
proofs to storage for recovery without waiting for a full handoff channel.

This is an unreleased implementation change; verify the node build before
assuming that an older binary honors this setting.

### proving_priority

| Value | Behaviour |
|-------|-----------|
| `sequential` | Prove blocks in ascending order. Preferred for archival integrity. |
| `latest-first` | Compute newer eligible ranges first within a bounded contiguous window. Results are persisted and submitted in source order. |

The latest-first scheduler reserves up to twice `max_concurrent_proofs` eligible
proof ranges from the canonical frontier. At most `max_concurrent_proofs` CPU
workers take ranges from the newest end of that window. The entire window drains
before more work is admitted, so new arrivals cannot indefinitely postpone older
reserved ranges. Gaps and below-threshold ranges remain queued under the same
strict settlement rules. Even with one worker, newer ranges in the window are
computed first; proof publication still waits for their predecessors.

Priority scheduling is an unreleased implementation change. Older binaries may
parse the setting without changing the actual proving order.

---

## ProofAmendment Lifecycle

```
prove_sig_batch()
    │
    └─► ProofAmendment {
          version: 1,
          block_hash,
          block_number,
          proof: SigBatchProof {
            batch_root_bytes: [u8; 16],  // final accumulator (STARK public output)
            n_sigs: usize,               // number of signatures covered
            proof_bytes: Vec<u8>,        // raw Winterfell STARK proof
          },
          prover: Address,
          prover_signature: Bytes,       // PQ sig over sha3(b"proof-amendment" ‖ block_hash ‖ block_number ‖ batch_root)
        }
```

On receipt, the network:
1. Checks `prover` is in `ProverRegistry`
2. Verifies `prover_signature` with the PQ public key bound to the registered address
3. Verifies the `SigBatchProof` (Winterfell STARK verification)
4. Stores at `pa/<block_hash>`
5. Deletes `w/<block_hash>` (after grace window)

When `L2StarkMode=Active`, a proof challenge remains open for `T_c = 7200` blocks
before the amendment lifecycle resolves to `RESOLVED` or `SLASHED`.

---

## Monitoring

Scrape the configured metrics listener (port 9090 by default):

```bash
curl --fail --silent http://127.0.0.1:9090/metrics
```

Use these exact Prometheus series names:

```text
# Locally generated L1 proofs delivered to the node event loop (process lifetime)
shell_stark_proofs_generated_total
# CPU proof-attempt time, excluding queueing and ordered publication waits
shell_stark_proof_duration_seconds_count
shell_stark_proof_duration_seconds_sum
shell_stark_proof_duration_seconds_bucket{le="1"}
# Failed proof jobs; they do not increment the successful-proof counter
shell_stark_proof_failures_total
# Queued proof tasks, including below-threshold work; excludes reserved jobs
shell_stark_backlog_depth
# Generated proofs awaiting canonical settlement
shell_stark_pending_settlements
# Authenticated amendments rejected by admission limits
shell_stark_amendments_rate_limited_total

# Cached storage byte estimates, refreshed every 300 seconds
shell_storage_cf_size_bytes{cf="witness"}
shell_storage_cf_size_bytes{cf="proof"}

# Local production accepts settlements; imported settlements do not increment this counter
shell_stark_settlements_accepted_total
# Amendments rejected during validation
shell_stark_settlements_rejected_total
# Canonical source blocks not yet settled at L1
shell_stark_frontier_lag
```

Counters and histogram samples reset when the process restarts; durable prover
registration counts are queried separately with `shell_getRegisteredProver`.
A generated proof is not necessarily accepted into the chain: check its settlement
transaction receipt and the canonical prover record as well. The duration histogram
records successful and failed CPU attempts. Waiting for enough entries or a missing
source does not produce a duration sample or a proof failure.

Storage estimates include keys and values under the witness and proof prefixes.
Proof size varies with the source range and encoding; it is not a fixed number of
bytes per block. Witness retention and the settled frontier govern pruning, so a
nonzero witness estimate alone does not indicate a failure.

The generation-duration, failure-count and live-backlog updates are an unreleased
implementation change. Older binaries expose these series but may leave them at
zero. Previous guide examples using `shell_prover_*` or unprefixed settlement
names did not match the exported series.

Proof generation remains paused while the node is synchronizing or otherwise
fails its readiness gate. A prover keeps at most two generated amendments in
flight until canonical settlement releases capacity. Sustained growth in
`shell_stark_amendments_rate_limited_total`, especially together with a stalled
chain head, indicates peer pressure or a settlement-path failure and should be
investigated before increasing any limits.


---

## Proof Challenge Mechanism

If a node receives a `ProofAmendment` it cannot verify, it may broadcast a
`ProofChallenge` to the network:

```
ProofChallenge {
  block_hash,
  sequence,                        // monotonic sequence (rate-limited)
  reason: VerificationFailed       // or InvalidBatchRoot
           | InvalidProverSignature
           | UnregisteredProver,
  challenger: Address,
}
```

Any node holding the raw proof can respond with a `ChallengeResponse` carrying
the proof bytes, allowing the challenger to retry verification. Challenge windows
close after `T_c = 7200` blocks; at that point the amendment is resolved or the
prover is slashed, depending on the verification outcome. Challenges are
rate-limited per-peer to prevent DoS. A prover that accumulates failed
challenges may be removed from `ProverRegistry`.

## Local acceptance

From a compatible source checkout, run:

```bash
cargo build -p shell-cli --bin shell-node --features libp2p
cargo build -p shell-node --example prover-acceptance
python3 tests/e2e/prover-registration.py
```

The script creates fresh keys and isolated Dev1337 nodes with explicit activation,
registers an independent prover, sends 512 signed transfers, verifies the actual
STARK and tamper rejection, and checks replicated settlement counters and restart
persistence. It stops its processes and keeps private temporary data and receipts
for inspection. This local acceptance does not activate any public network.
