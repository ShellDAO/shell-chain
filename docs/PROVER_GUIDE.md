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

The `ProverRegistry` (in `shell-consensus`) maintains a list of registered
provers. Only registered provers can submit `ProofAmendment` messages.

### Registering a prover

Provers register by submitting a governance transaction through
`shell_proposeAddValidator` with the prover's address. The prover's address is
derived from its PQ public key the same way as any account:
`blake3(version || algo_id || pubkey)[0..20]`.

### ProverRecord fields

| Field | Description |
|-------|-------------|
| `address` | Prover's address |
| `pubkey` | Dilithium3 public key (for `ProofAmendment` signature verification) |
| `registered_at` | Block height of registration |
| `proofs_submitted` | Lifetime proof count |
| `last_proof_block` | Most recently proved block number |

---

## Running a Prover Node

A prover node does not need a validator keystore. It needs:

1. A PQ key for signing `ProofAmendment` messages
2. Registration in `ProverRegistry`
3. Access to a synced peer (or full P2P participation)

### Step 1: Generate a prover key

```bash
shell-cli keygen --algo dilithium3 --out /data/prover-keystore.json
# Enter passphrase when prompted
```

### Step 2: Config

```toml
# prover.toml
[node]
datadir = "/data/prover"
chain_id = 31337
node_role = "prover"
# No keystore needed for block production

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
enable_stark_aggregation = false  # set true to enable ProofAmendment flow

[prover]
max_concurrent_proofs = 1         # parallel proof jobs
proving_priority = "sequential"   # "sequential" (oldest first) | "latest-first"

[pruning]
proof_replacement_grace = 0       # blocks to keep WitnessBundle after proof arrival
                                  # 0 = delete immediately (default, recommended)
```

### proving_priority

| Value | Behaviour |
|-------|-----------|
| `sequential` | Prove blocks in ascending order. Preferred for archival integrity. |
| `latest-first` | Prove newest blocks first. Useful when the prover is catching up — recent blocks get proofs sooner. |

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
2. Verifies `prover_signature` with the registered Dilithium3 pubkey
3. Verifies the `SigBatchProof` (Winterfell STARK verification)
4. Stores at `pa/<block_hash>`
5. Deletes `w/<block_hash>` (after grace window)

---

## Monitoring

Key Prometheus metrics for prover operators:

```
# Proof generation
shell_prover_proofs_generated_total          — lifetime proofs submitted
shell_prover_proof_duration_seconds          — histogram of proof generation time
shell_prover_queue_depth                     — pending blocks awaiting proof

# Storage
shell_storage_cf_size_bytes{cf="witness"}    — should trend toward 0 when STARK is active
shell_storage_cf_size_bytes{cf="proof"}      — grows ~15 KB/block
```

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
the proof bytes, allowing the challenger to retry verification. Challenges are
rate-limited per-peer to prevent DoS. A prover that accumulates failed
challenges may be removed from `ProverRegistry`.
