---
title: "Why We Built Native Account Abstraction — and Why ERC-4337 Wasn't Enough"
date: 2026-04-19
author: Shell Chain Team
excerpt: Shell Chain implements account abstraction at the protocol layer, not as an overlay. Here's why we made that choice and how the architecture works.
tags: [account-abstraction, architecture, post-quantum, design]
---

## The Problem with Bolt-On Abstraction

ERC-4337 is clever engineering. It achieves account abstraction on Ethereum
without a hard fork by introducing a new transaction type (`UserOperation`),
an off-chain bundler market, and a singleton `EntryPoint` contract that
orchestrates validation and execution. For Ethereum, constrained by backward
compatibility, this was probably the right move.

Shell Chain has no such constraint. We designed the chain from scratch for a
post-quantum world, and that freedom meant we could ask a more fundamental
question: **what would account abstraction look like if you built it in from
day one?**

The answer looks different from ERC-4337 in almost every dimension.

---

## What "Native" Actually Means

In Shell Chain, every account is a smart account. There is no concept of an
"externally-owned account" (EOA) in the traditional ECDSA sense. Every
transaction goes through the same three-layer validation pipeline:

```
Layer 1: Protocol-level signature check (Dilithium3 or SPHINCS+)
              ↓
Layer 2: Account-specific validation contract (if set via AccountManager)
              ↓
Layer 3: EVM execution
```

The critical difference: validation happens **before** the EVM sees the
transaction. No bundler. No `UserOperation` mempool. No `EntryPoint` contract
to re-enter. The chain itself is the bundler.

---

## Why We Rejected ERC-4337 for Shell Chain

### 1. The PQ problem

ERC-4337 validates `UserOperations` using `ecrecover` — the ECDSA precompile
at `0x01`. We disabled that precompile entirely (it returns empty bytes). Our
transaction model uses Dilithium3, a NIST-standardized lattice-based signature
scheme with 3,309-byte signatures and ~1,952-byte public keys.

Trying to shoehorn this into ERC-4337's signature flow would have required
every account to deploy a custom validator contract just to do basic transaction
signing. That's not abstraction — that's complexity for its own sake.

### 2. The address binding problem

Ethereum addresses are `keccak256(pubkey)[12:]`. If your public key changes
(key rotation after a compromise), your address changes — you lose your account
identity, token balances, and contract permissions.

Shell Chain addresses are `blake3(version || algo_id || pubkey)[0..20]`.
The `version` field makes the scheme forward-extensible; the `algo_id` binds
the address to the algorithm, not the specific key. When you rotate your key
via the `AccountManager` system contract, your address stays the same. The
chain updates the registered public key; future transactions are validated
against the new key.

This is non-negotiable for a post-quantum system. NIST expects users to rotate
keys as algorithms evolve. The blockchain identity layer must support that.

### 3. The bundler market problem

ERC-4337 depends on an off-chain bundler market to aggregate `UserOperations`
into on-chain transactions. This introduces new trust assumptions:
- Bundlers can censor UserOperations
- Bundler competition is needed to prevent monopolistic fee extraction
- UserOperation mempools are separate from the main mempool, adding client complexity

Shell Chain's approach eliminates the bundler entirely. Transactions arrive at
the P2P mempool the same way for all accounts. Custom validation contracts are
called synchronously during block production — not by external infrastructure.

---

## The Architecture

### AccountManager System Contract (`0x02`)

```
User calls AccountManager.rotateKey(newPubkey, algoId)
                   ↓
WorldState updates: account.pubkey = newPubkey
                   ↓
All future transactions validated with new key
Address unchanged: blake3(version || algo_id || old_pubkey)[0..20]
                   ← wait, this is the same address!
```

Actually, Shell Chain's key rotation is smarter: the address is computed once
at account creation. The `AccountManager` contract stores the current active
public key separately from the address. This is what enables rotation without
address change.

### Custom Validation Code

```
User calls AccountManager.setValidationCode(codeHash)
                   ↓
Account stores: validation_code_hash = keccak256(validator_bytecode)
                   ↓
On each transaction:
  if account.has_validation_code():
    call validator.validateTransaction(txHash, sig, pubkey)
    require return value == VALIDATION_SUCCESS_MAGIC
  else:
    use default Dilithium3 check
```

The validator contract receives a **snapshot** of the world state at the
beginning of the block — it can read any storage but its writes are discarded.
This prevents validation from affecting execution state, avoiding a whole class
of reentrancy-style validation attacks.

### Gas cap

Custom validation is capped at `500,000 gas`. This prevents validation DoS
where a malicious contract loops forever.

---

## What This Enables

**Multisig without special account types:** Deploy a validator contract that
requires M-of-N Dilithium3 signatures. Any account can use it by calling
`setValidationCode`. No multisig wallet factory needed.

**Social recovery:** A validator contract that accepts recovery signatures from
designated guardians. The account sets this as its validation code; guardians
can authorize key rotation if the primary key is lost.

**Time locks and spending limits:** Validation contracts can inspect transaction
calldata and impose rules — "this account cannot transfer more than X tokens per
block" — enforced at the protocol level, not by a guardian contract.

**Quantum-safe by default:** All of this runs with Dilithium3 as the base layer.
There's no ECDSA anywhere in the transaction lifecycle.

---

## What We Preserved

**EVM compatibility.** Contracts still see standard 20-byte addresses in
`msg.sender`, `tx.origin`, storage mappings, events. Existing Solidity code
doesn't need changes. The PQ plumbing is below the EVM's line of sight.

**EIP-1559 fees.** Same gas model, same `baseFeePerGas` mechanics. The
abstraction layer doesn't touch fee calculation.

**Standard wallet UX.** The `pq1...` Bech32m address format is the only
user-facing change. Behind it, everything behaves like a normal EVM chain.

---

## The Road Ahead

Shell Chain's AA foundation is production-ready. What we're building next:

- **Batch transaction support:** validate once, execute N transactions in sequence
- **Sponsored transactions:** a third party pays gas for another account's transaction
- **ZK-validated accounts:** validator contracts that verify ZK proofs rather than
  raw signatures — potentially useful for privacy-preserving AA schemes

The native approach means these features are first-class protocol improvements,
not smart contract hacks stacked on top of hacks.

---

*Read more: [Native Account Abstraction Guide](/docs/account-abstraction) ·
[System Contracts](/docs/system-contracts) · [PQ Crypto Guide](/docs/pq-crypto)*
