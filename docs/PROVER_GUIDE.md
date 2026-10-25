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


### worker_cohort (unreleased)

For a fixed group of L1 workers, put the same list of their distinct prover
addresses in each worker's configuration. Every worker must use its own key,
be registered under the network's existing prover-registry rules, and follow
the same canonical chain. For example, after replacing both values with the
actual 32-byte addresses of two registered workers:

```toml
[prover]
worker_cohort = [
  "0x1111111111111111111111111111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222222222222222222222222222",
]
```

The node sorts the addresses, chooses one owner from the first canonical source
hash of each minimum-size L1 range, and runs CPU proving only on that owner.
Other workers retain bounded reservations while observing the resulting proof.
Range boundaries do not depend on how many later blocks a worker has received.
Proof authentication, canonical settlement ordering, and rewards retain their
normal validation rules. A valid later L1 proof may finish before its predecessor;
it is stored and broadcast while waiting, but cannot settle across the gap.
Ordinary validators recover stored proofs at the canonical frontier without
starting CPU proving tasks.
Cached proofs prevent recomputation after reopening, including while waiting
for an earlier worker to finish.

The cohort is persisted in each local prover database. Reordered lists are
accepted; duplicate addresses, a missing local signer, and a different list on
reopen are rejected. Restore the original configuration after an accidental
change. Do not delete chain data to bypass a membership error.

The initial cohort supports at most 64 workers. To coordinate a later change,
stop every participating worker, ensure they have synchronized, and append the
same future epoch to every worker's full configuration before restarting:

```toml
[[prover.worker_cohort_schedule]]
from_block = 1000000
workers = [
  "0x2222222222222222222222222222222222222222222222222222222222222222",
]
```

Replace the sample height with one beyond **all** workers' persisted canonical
heads, leaving time to restart and synchronize before it is reached. The example
retires the first worker for new ranges; it remains responsible for older ranges.
Register each incoming identity using the normal registry rules before its first
assignment. A local key must occur in at least one configured epoch. Keep retired
workers online until their old assignments settle.

Ownership is selected by the **first source block** of a range. A range that
starts before `from_block` and ends after it stays with the old membership;
the first range starting at or after that height uses the new membership.
No small, invalid proof range is created by splitting at the boundary.

There may be at most 63 future epochs, with strictly increasing heights. Once
persisted, every epoch is immutable, including announced future entries. You may
append an epoch only beyond the local canonical head. Removing, rewriting or
backdating an epoch fails before listeners or proving start. Restoring the full
original schedule recovers from an accidental edit. Scheduled databases reject
static-only configuration and older static-only binaries on reopen; use a build
supporting this schedule on every worker. A fresh joining database needs the full
historical schedule to reconstruct the same ownership.

This is an explicitly coordinated operational plan. It does not automatically
recruit registered provers or transfer an offline worker's assignments. All
workers must use the same schedule; there is no network negotiation of different
operator configurations. Do not assume exactly-once computation across partitions
or crashes. Omitting both settings on a fresh database retains independent
scheduling. This feature is unreleased; older public binaries may ignore these
settings and generate duplicate work.

Build a node with RocksDB and libp2p, then run the isolated acceptance with Node.js
and a compatible Shell SDK build (transaction wire format v2):

```sh
SHELL_NODE_BIN=./target/debug/shell-node \
SHELL_SDK_ENTRY=../shell-sdk/dist/index.js \
node tests/e2e/prover-cohort.mjs
```

The entry creates fresh keys and an isolated three-node chain, registers two
provers, submits 512 genuine one-wei transfers, and requires exactly one generated
proof across the workers. It checks the finalized receipts and balances, rejects
a changed persisted cohort, and reopens all three RocksDB nodes without proof
recomputation. To also test a coordinated membership change, use the same command
with `SHELL_COHORT_RECONFIGURE=1`. That mode sends 1,536 transfers, requires an
unsplit range crossing the activation and a later proof from the new member,
rejects a backdated append, history rewrite and static downgrade, and reopens
all databases with the schedule intact. Use `SHELL_COHORT_LATE_JOIN=1` to also
exercise a freshly initialized third prover that occurs only in the future
membership. It registers that identity after the initial proof, requires live
historical synchronization without old-work generation, checks future ownership,
and reopens all four native nodes with receipts and prover records intact.
This option includes the coordinated-membership checks above.

For completion in reverse order, use `SHELL_COHORT_DELAY_PREDECESSOR=1` with the
same command, separately from the other two options. It accumulates 1,024 signed
transfers, starts only the later range's scheduled owner, and checks that its
proof is stored without settling across the gap. It reopens those databases
before starting the earlier owner, then requires both original proofs to settle
once in source order, with their exact rewards. All three databases reopen again
with the balances, nonces, finalized hashes and prover counters intact. This
controls worker startup order; it does not transfer an absent owner's work.

For a bounded concurrency check, use `SHELL_COHORT_PARALLEL=1` separately from
all other options. It accumulates 1,024 genuine transfers and synchronizes the
workers as validators before restarting both as isolated dev provers while the
authority is stopped. It then reconnects the native nodes and requires settlement
from those persisted proofs without regeneration. It requires overlapping
start/finish intervals recorded inside the two actual CPU proof calls, distinct
input-derived ranges, exactly one generated proof per worker, ordered settlement
with exact rewards, and consistent state after reopening all three databases.
The validator must generate no proof. An overlap failure leaves concurrency
unqualified even when settlement succeeds. This local workload does not measure
throughput, speedup or CPU core utilization.

Persisted L1 frontier proofs are re-advertised directly to newly connected
peers and on the existing periodic retry. Recovery admits at most the two pending
settlement slots, rechecks canonical order, prover authentication and source
binding, and retains artifacts on storage or transport errors. A later proof
waits for its predecessor; settled proofs stop retrying. This does not move work
from an absent owner.

The entry retains private keys and databases for inspection and stops its own
processes. It does not qualify automatic recruitment, failover or production scale.

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

Incoming challenges use a separate token bucket per network peer: ten initial
requests, refilling five tokens every 60 seconds up to the initial capacity.
Changing the claimed `challenger` address does not create another allowance.
Excess requests are dropped before tracking the challenge or reading and sending
proof data; they do not consume the prover's settlement-submission allowance.
Idle peer buckets expire after 600 seconds. These limits reset on process restart.
This receive-side enforcement is an unreleased implementation change; older
binaries do not apply this challenge limit.

Challenge responses carry a serialized `ProofAmendment`, including the full STARK
proof and the prover's authenticated signature envelope. The receiver checks the
signature and its binding to the prover address before validating the source range
or writing proof artifacts. When `prover_registry_height` is active at the next
block height, that prover must also be registered. A relay may forward another
prover's signed amendment; the claimed `responder` address is not a substitute
for proof authentication. Rejected responses leave the challenge open and do not
write any proof-range artifacts. A valid response stores the proof and resolves
the challenge; this alone does not settle a reward or increment registration counts.
This response-admission correction is unreleased; verify the node build before
relying on this behavior in an older binary.

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

For receive-side challenge admission, run:

```bash
cargo test -p shell-node event_loop_limits_challenges_per_peer_before_tracking
cargo test -p shell-node event_loop_authenticates_challenge_responses_before_storage
```

This exercises the running node event loop through serialized in-process peer
messages. It checks claimed-address rotation, rejected lifecycle entries and
independent peer allowances; it does not simulate a 7,200-block challenge timeout.

The response-admission regression uses fresh Dilithium identities, 512 signed
transfers and a verified STARK proof through the serialized in-memory peer transport.
It checks tampering, signer identity, relay forwarding, unchanged state on rejection,
and disabled/before/at/after registration activation. It does not cover GossipSub
transport, other signing algorithms, or challenge recovery after process restart.
