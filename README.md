# shell-chain

> The official Rust implementation of the Shell blockchain protocol. 
> Designed from genesis for Post-Quantum (PQ) security, stateless verification, and witness separation.

## Key Architecture & Features

`shell-chain` implements the cutting-edge concepts established in the [Shell Protocol Specs](../specs/):

*   **PQ-Native Cryptography**: Built as a first-class citizen without legacy EOA/ECDSA baggage. Supports NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) post-quantum signatures out of the box.
*   **Witness Separation**: Transactions and their massive structured cryptographic proofs ("Witnesses") are strictly decoupled into execution Envelopes and decoupled Sidecars.
*   **Dual-Lane Fee Market**: Independent pricing rails for standard execution logic (`regular`) and specific PQ cryptographic bandwidth (`max_witness_priority_fee`).
*   **Unified Binary Tree**: A JMT-style state accumulator driven by PQ-safe SHA-256 caching. Discards archaic 256-level SMTs for optimal `O(log2(N))` inclusion proofs.
*   **Pure SSZ Serialization**: Fully embraces Simple Serialize (SSZ) from the Ethereum Consensus Layer. Enforces native merkleization guarantees.

## Crate Structure

The workspace strictly adheres to dependency isolation and domain decoupling principles:

*   **`shell-primitives`**: SSZ definitions, `U256`/`H256` aliases, and wire-level types.
*   **`shell-crypto`**: PQ signature wrappers and standardized SHA-256 boundaries.
*   **`shell-state`**: The Unified Binary Tree core and state transition sandbox.
*   **`shell-execution`**: Transaction processing and EVM compatibility layer.
*   **`shell-mempool`**: Sidecar-aware P2P transaction buffering with "Cheap-First, Heavy-Last" admission rules.
*   **`shell-consensus`**: Block building, envelope matching, and attestation rules.
*   **`shell-network`**: Gossipsub propagation, node discovery, and robust state sync via Fetch-on-Demand.
*   **`shell-cli`**: Node entry point, configuration, and RPC servers.

## Specifications

This repository serves strictly as the *implementation layer*.

*   📖 **Implementation Specs**: See `./specs/` for internal layout, testing vectors, and validation crate assignments.
*   📖 **Protocol Specs**: See `../specs/protocol/` in the parent `shell-core` repository for the true Wire-Level Truth.

## Building & Testing

```bash
# Clone the monorepo with submodules
git clone --recursive https://github.com/LucienSong/shell-core.git
cd shell-core/shell-chain

# Build the client
cargo build --release

# Run protocol specification test vectors
cargo test
```