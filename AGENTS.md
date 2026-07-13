# AGENTS.md — shell-chain

Local single-source-of-truth for AI agents working inside this repository.
This file is fully self-contained; it does not reference any file outside
this submodule.

## What this repo is

The post-quantum-native Layer 1 node implementation:

- PQVM-native execution, currently through a revm-backed adapter for retained
  Cancun-style arithmetic, memory, storage, and control-flow semantics
- PQ signatures: ML-DSA-65 primary (FIPS 204), Dilithium3 legacy-compatible active path, SPHINCS+ fallback
- wPoA consensus engine
- STARK transaction-level settlement (system tx, no `extra_data`)
- Account Abstraction natively in protocol (tx type `0x7E`)
- RocksDB storage with three-segment witness pruner

Currently at **v0.27.1**.

## Read order before editing

This repository ships a public, self-contained agent SSoT (this file).
Operators may also maintain a private `docs/agents/` subtree locally
(gitignored, not distributed) containing CONSTITUTION, ARCHITECTURE,
ADRs, learnings, and per-crate feature specs. If that subtree is
present in your working copy, treat the white paper as the target
protocol authority and use the local docs as derived operational
invariants: `CONSTITUTION.md` → `ARCHITECTURE.md` → `learnings.md` →
relevant `features/<crate>/spec.md` → relevant ADR.

If `docs/agents/` is not present, this file plus `CHANGELOG.md`,
`docs/CONSENSUS_DETAILS.md`, `docs/stark-aggregation.md`,
`docs/BLOCK_PRUNING_AND_COMPRESSION.md`, `docs/ACCOUNT_ABSTRACTION_GUIDE.md`,
and the `crates/*/src/` source are the canonical references.

## Quick commands

```bash
make ci            # fmt --check + clippy -D warnings + test --workspace (CI parity)
make test          # cargo test --workspace --tests
make bench         # cargo bench --workspace
make bench-quick   # compile-check benches only
make e2e           # tests/e2e/run-e2e.sh (requires Docker)
make load-test     # tests/e2e/run-load-test.sh
make chaos-test    # tests/e2e/run-chaos-test.sh
```

Single test: `cargo test -p <crate> <test_name> -- --nocapture`.
Toolchain uses the `stable` channel via `rust-toolchain.toml` (+ rustfmt + clippy).

## Crate map (15 crates)

| Crate | Role |
|---|---|
| `primitives` | Core types (ShellHash, Address, U256) |
| `crypto` | PQ signature stack (ML-DSA-65 primary / Dilithium3 legacy-compatible / SPHINCS+ fallback) |
| `core` | Shared trait definitions, transaction model |
| `storage` | KvStore, witness pruner, settled-source index |
| `consensus` | wPoA engine, validator set, slashing |
| `genesis` | Genesis block construction |
| `pqvm` | revm-backed PQVM execution adapter, parallel scheduler |
| `mempool` | Transaction pool |
| `network` | libp2p gossipsub |
| `rpc` | JSON-RPC, TLS, three-RPC fanout |
| `keystore` | PQ keystore (argon2id + XChaCha20-Poly1305) |
| `stark-prover` | STARK AIR + ProverService |
| `node` | NodeBuilder, ProverService orchestrator, AA, system_rewards |
| `cli` | `shell-chain` binary |
| `bench` | Criterion benches (dev-only) |

For a deeper per-crate spec, consult the operator-local
`docs/agents/features/<crate>/spec.md` if present.

For navigating `crates/node/` specifically, see
`crates/node/MODULES.md` (logical group map).

## Cardinal rules

- **White paper precedence**: target protocol behavior is defined by the
  Shell-Chain white paper. If an operator-local `docs/agents/CONSTITUTION.md`
  is present, treat it as derived operational invariants — flag drift,
  do not silently reconcile.
- **All PQ signatures verified at mempool entry.**
- **STARK proof settlements**: only via the `StarkReward` system
  transaction. `BlockHeader::extra_data` is permanently deprecated as a
  settlement carrier.
- **Witness pruner cutoff** is always
  `min(retention_cutoff, stark_frontier)`.
- **Drain-frontier** is an `Arc<AtomicU64>` that is monotonic per process;
  the seeder must clamp `scan_start` to
  `max(contiguous_pending_end - 16, drain_frontier)`.
- **`L2StarkMode::Active` is allowed only when the deployment explicitly
  opts into the white-paper STARK target path and its operational gates.**

## Quality gates (local mirror of CI)

A change is mergeable when:

1. `cargo fmt --check` passes
2. `cargo clippy --workspace -- -D warnings` passes
3. `cargo test --workspace` passes
4. New protocol invariants are recorded somewhere durable (operator
   CONSTITUTION if maintained, otherwise CHANGELOG and the relevant
   `docs/` file)
5. Non-obvious design choices are recorded in an ADR (operator-local if
   the `docs/agents/adrs/` subtree is in use)

## Commit / PR conventions

- **Conventional Commits**: `<type>(<scope>): <subject>` —
  `type ∈ {feat, fix, docs, test, refactor, chore, ci}`. Scope is a
  crate or module name (e.g. `crypto`, `consensus`, `rpc`, `ops/faucet`).
- Branches: `feat/<feature-id>`, `fix/<issue-id>`, `docs/<topic>`,
  `chore/<topic>`, `release/v<version>`.
- Commit messages and code comments are **English**. PR/Issue
  descriptions may be Chinese.
- AI-authored commits include a `Co-authored-by: Copilot
  <223556219+Copilot@users.noreply.github.com>` trailer.

## Things to never commit

Secrets, private keys, `*.keystore.json`, keystore password files, `.env`,
local node data (`/opt/shell/...`), `testnet-backup-*/`, any generated
runtime artifact.

## Tool pointers (this file is the SSoT)

- `CLAUDE.md` → read this file
- If your tool reads `.cursor/rules/*.mdc` or `.github/copilot-instructions.md`, treat `AGENTS.md` as the canonical source — these pointer files are not maintained in this repository.
