---
title: "Why STARK Proofs for Signature Aggregation — and How We Built It with Winterfell"
date: 2026-04-19
author: Shell Chain Team
excerpt: Shell Chain uses STARK proofs to compress thousands of post-quantum signatures into a single 15 KB proof. Here's why we chose STARKs over SNARKs, and how the Winterfell-based implementation works.
tags: [stark, cryptography, scalability, architecture]
---

## The Post-Quantum Signature Problem

Dilithium3 signatures are 3,309 bytes each. Public keys are ~1,952 bytes (stored
once per new sender). A block with 100 transactions carries roughly **390 KB of
signature data** — before you count transaction payloads.

For comparison, an Ethereum block's ECDSA signatures account for about 6.4 KB
(64 bytes × 100 txs). We're roughly **60× larger per block** just for
cryptographic authentication.

This is the unavoidable cost of post-quantum security. The question isn't
whether to pay it — it's whether you have to pay it *forever*.

---

## The Insight: Signatures Are Ephemeral, Proofs Are Permanent

A Dilithium3 signature exists for one purpose: proving that the private key
holder authorized this transaction. Once a proof system can independently
certify "all N signatures in block B were valid," the original signatures
become redundant.

This is what Shell Chain's STARK aggregation does:

```
Block sealed with N Dilithium3 signatures (stored as WitnessBundle)
        ↓
Prover runs SigBatchCircuit over all N signatures
        ↓
ProofAmendment{SigBatchProof} ≈ 15 KB  (constant regardless of N)
        ↓
Original WitnessBundle (~4 KB/tx) deleted
```

At 100 tx/block: **390 KB → 15 KB**. A **26× compression ratio** that grows
linearly with transaction count.

---

## Why STARKs Over SNARKs

We evaluated several proof systems before settling on STARKs.

### The trusted setup problem

Most practical SNARKs (Groth16, PLONK, Marlin) require a trusted setup ceremony
— a multi-party computation that produces public parameters. If the ceremony is
compromised, a malicious prover can forge proofs indistinguishable from valid
ones. This is an operational and trust assumption we wanted to avoid entirely.

STARKs have **no trusted setup**. Security relies only on collision-resistant
hash functions — which, unlike elliptic curve discrete log, have a clear
post-quantum security story (double the output size for 128-bit PQ security).

### The transparency and auditability argument

A STARK's proof system is fully transparent. The AIR (Algebraic Intermediate
Representation) that encodes the computation is public and can be independently
audited. There's no "toxic waste" from a setup ceremony that must be destroyed
and trusted to have been destroyed.

For a chain whose threat model explicitly includes well-funded adversaries
(including nation-state actors preparing for the post-quantum era), eliminating
setup ceremony risk is worth the larger proof size.

### Proof size vs. verify time

SNARKs have smaller proofs (typically 128–256 bytes for Groth16) and fast
on-chain verification. STARKs are larger (our Winterfell proofs are 10–20 KB)
with slower verification.

For Shell Chain's use case — **off-chain batch verification, not on-chain
per-tx verification** — this tradeoff is acceptable. The proof is verified once
by each peer when it receives the `ProofAmendment`; it doesn't need to be
re-verified by an EVM contract on every query.

### FRI and concrete security

Winterfell uses FRI (Fast Reed-Solomon Interactive Oracle Proof) as its PCS
(polynomial commitment scheme). FRI's concrete security is well-understood:
it relies on the random oracle model and the hardness of solving certain
proximity problems in Reed-Solomon codes — problems that don't have known
quantum speedups beyond a square-root (Grover) factor.

By choosing a STARK over a SNARK, we get:
- No trusted setup
- Post-quantum sound security (with large enough field elements)
- Transparent, auditable proof system
- No pairing-based cryptography (pairing-friendly curves have unclear PQ security)

---

## The Implementation: SigBatchCircuit on Winterfell

### Circuit design

The `SigBatchCircuit` is a Winterfell AIR that encodes the following statement:

> "For each of the N (pubkey, message, signature) tuples in this batch, the
> Dilithium3 verification algorithm outputs 'valid'."

The trace layout:

| Column | Content |
|--------|---------|
| 0..k | Expanded signature state (verification intermediate values) |
| k | Boolean: signature i is valid |
| k+1 | Running accumulator (batch_root) |

At each row, the AIR enforces the Dilithium3 polynomial multiplications and
modular reductions. The final row's `batch_root` column is the public output
(committed to in the `ProofAmendment`).

### SigBatchProof structure

```rust
pub struct SigBatchProof {
    pub version: u8,
    pub batch_root_bytes: [u8; 16],  // final accumulator (public output)
    pub n_sigs: usize,
    pub proof_bytes: Vec<u8>,        // raw Winterfell Proof
}
```

`batch_root_bytes` is a 128-bit field element — the Winterfell field is
`F_p` where `p = 2^64 - 2^32 + 1` (a 64-bit Goldilocks-like prime).

### ProofAmendment broadcast

```rust
pub struct ProofAmendment {
    pub version: u8,
    pub block_hash: ShellHash,
    pub block_number: u64,
    pub proof: SigBatchProof,
    pub prover: Address,
    pub prover_signature: Bytes,  // Dilithium3 sig over (block_hash ‖ block_number ‖ batch_root)
}
```

The `prover_signature` prevents forgeries: any node can verify that a registered
prover actually ran the computation, not that an attacker injected a false proof
claiming all signatures were valid.

### Verification on the receiving peer

```
Receive ProofAmendment
    │
    ├─ Check prover ∈ ProverRegistry
    ├─ Verify prover_signature (Dilithium3)
    └─ Verify SigBatchProof via verify_sig_batch()
           │
           ├─ Reconstruct public inputs from block's WitnessBundle
           ├─ Run Winterfell verifier (FRI + DEEP-ALI)
           └─ Check batch_root matches claimed value
```

If all checks pass: store `pa/<hash>`, delete `w/<hash>`.

---

## The Storage Architecture

The STARK pipeline integrates with Shell Chain's three-segment block storage:

```
b/<hash>  — StrippedBlock (TX detail)       ← permanent
w/<hash>  — WitnessBundle (PQ signatures)   ← deleted after proof
pa/<hash> — ProofAmendment (STARK proof)    ← permanent
```

This means:
- **Explorers** always have full transaction history (from `b/`)
- **Verifiers** always have cryptographic proof of block validity (from `pa/`)
- **Disk space** recovers the 390 KB WitnessBundle once the 15 KB proof arrives

---

## Asynchronous Proving: Design Choices

### Why async?

Dilithium3 verification is fast (~1ms per signature on modern hardware).
STARK proof generation for a 100-tx batch takes significantly longer — on the
order of seconds to minutes depending on hardware and circuit complexity.

Block production cannot wait for proofs. The chain would stall.

Instead, Shell Chain separates consensus time from proof time:
1. Block is sealed and propagated immediately (using native signature verification)
2. A prover node generates the proof in the background
3. `ProofAmendment` is broadcast and attached after the fact

The proof doesn't need to be ready before the next block. It just needs to
arrive before the block is pruned from witness storage.

### The grace window

`proof_replacement_grace` (default: 0 blocks) controls how long to keep the
`WitnessBundle` after a proof arrives. For production use with STARK nodes,
the default is immediate deletion. For forensic or debugging use:

```toml
[pruning]
proof_replacement_grace = 604800  # keep for ~7 days at 1 block/s
```

### Proving priority

For prover nodes catching up after downtime:

```toml
[prover]
proving_priority = "latest-first"  # prove newest blocks first
```

This ensures recent blocks get proofs quickly even if historical blocks are
waiting — useful when disk pressure from WitnessBundles is more urgent than
archival completeness.

---

## Benchmarks

From our Criterion benchmarks on Apple M-series hardware:

| Scenario | WitnessBundle | + ProofAmendment | Savings |
|----------|--------------|-----------------|---------|
| 10 tx/block | 39 KB | 15 KB | 62% |
| 50 tx/block | 195 KB | 15 KB | **92%** |
| 100 tx/block | 390 KB | 15 KB | **96%** |

At 50 tx/s sustained load, the STARK pipeline saves approximately **15 GB/day**
of disk space per full node. At 100 tx/s, that rises to **31 GB/day**.

---

## What's Next

### Recursive proofs

The current `SigBatchProof` proves one block at a time. A natural extension is
recursive aggregation: prove that a proof of block N and a proof of block N+1
are both valid, producing a single proof for both blocks. This would reduce
proof storage further and enable efficient light client verification.

### L3 trie pruning

The STARK-proven block history makes it possible to trustlessly prune state
trie nodes: a light client can verify the current state root is correct by
checking the STARK proof chain from genesis without replaying every transaction.
We've implemented the refcount infrastructure (`refs/<node_hash>`) and will
enable this once the proof chain is sufficiently mature.

### Multi-prover networks

Multiple registered provers compete to submit `ProofAmendments` first. The
first valid proof wins; duplicates are discarded. This creates an organic
proving market without special incentive mechanisms.

---

*Read more: [Block Pruning & Compression](/docs/block-pruning) ·
[Prover Guide](/docs/prover-guide) · [Benchmarks](/docs/benchmarks)*
