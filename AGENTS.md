# AGENTS.md — shell-chain

Local single-source-of-truth for AI agents working inside this repository.
This file is fully self-contained; it does not reference any file outside
this submodule.

## What this repo is

The post-quantum-native Layer 1 node implementation:

- Cancun-EVM compatible (revm-based executor)
- PQ signatures: Dilithium3 (NIST FIPS 204 / ML-DSA-65 path), SPHINCS+
- wPoA consensus engine
- STARK transaction-level settlement (system tx, no `extra_data`)
- Account Abstraction natively in protocol (tx type `0x7E`)
- RocksDB storage with three-segment witness pruner

Currently at **v0.22.2**.

## Read order before editing

1. **`docs/agents/CONSTITUTION.md`** — *highest authority*. On any conflict
   between code, spec, CHANGELOG, or README and the Constitution, the
   Constitution wins; flag drift, do not silently reconcile.
2. **`docs/agents/ARCHITECTURE.md`** — system overview, component graph,
   safety contract.
3. **`docs/agents/learnings.md`** — distilled patterns and pitfalls from
   prior development sessions (build, STARK, storage, ops, git, review).
4. The relevant **feature spec** at `docs/agents/features/<crate>/spec.md`.
5. The relevant **ADR** at `docs/agents/adrs/`.

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
Toolchain pinned by `rust-toolchain.toml` (stable + rustfmt + clippy).

## Crate map (15 crates)

| Crate | Role | Spec |
|---|---|---|
| `primitives` | Core types (ShellHash, Address, U256) | `docs/agents/features/primitives/spec.md` |
| `crypto` | PQ signature stack (Dilithium3 / ML-DSA-65 / SPHINCS+) | `docs/agents/features/crypto-core/spec.md` |
| `core` | Shared trait definitions, transaction model | `docs/agents/features/core-types/spec.md` |
| `storage` | KvStore, witness pruner, settled-source index | `docs/agents/features/storage/spec.md` |
| `consensus` | wPoA engine, validator set, slashing | `docs/agents/features/consensus-poa/spec.md` |
| `genesis` | Genesis block construction | `docs/agents/features/genesis/spec.md` |
| `evm` | revm wrapper, parallel scheduler | `docs/agents/features/evm-executor/spec.md` |
| `mempool` | Transaction pool | `docs/agents/features/mempool/spec.md` |
| `network` | libp2p gossipsub | `docs/agents/features/network-p2p/spec.md` |
| `rpc` | JSON-RPC, TLS, three-RPC fanout | `docs/agents/features/rpc-server/spec.md` |
| `keystore` | PQ keystore (argon2id + XChaCha20-Poly1305) | `docs/agents/features/keystore/spec.md` |
| `stark-prover` | STARK AIR + ProverService | `docs/agents/features/stark-prover/spec.md` |
| `node` | NodeBuilder, ProverService orchestrator, AA, system_rewards | `docs/agents/features/node-harness/spec.md` |
| `cli` | `shell-chain` binary | `docs/agents/features/cli/spec.md` |
| `bench` | Criterion benches (dev-only) | (no spec) |

For navigating `crates/node/` specifically, see
`crates/node/MODULES.md` (logical group map; ADR-005 explains why the
node crate is kept singular).

## Cardinal rules

- **CONSTITUTION precedence**: see "Read order" above.
- **All PQ signatures verified at mempool entry** (Constitution §7).
- **STARK proof settlements**: only via the `StarkReward` system
  transaction (Constitution clause P-1, ADR-002). `BlockHeader::extra_data`
  is permanently deprecated as a settlement carrier.
- **Witness pruner cutoff** is always
  `min(retention_cutoff, stark_frontier)` (clause P-3, ADR-007).
- **Drain-frontier** is an `Arc<AtomicU64>` that is monotonic per process;
  the seeder must clamp `scan_start` to
  `max(contiguous_pending_end - 16, drain_frontier)` (clause P-2, ADR-003).
- **`L2StarkMode::Active` is FORBIDDEN** until §13.1 promotion in the
  Constitution (clause P-4, ADR-004).

## Quality gates (local mirror of CI)

A change is mergeable when:

1. `cargo fmt --check` passes
2. `cargo clippy --workspace -- -D warnings` passes
3. `cargo test --workspace` passes
4. New invariants are reflected in `docs/agents/CONSTITUTION.md` (or
   flagged as drift)
5. New designs have a feature spec entry in `docs/agents/features/` and,
   if non-obvious, an ADR in `docs/agents/adrs/`

## Commit / PR conventions

- **Conventional Commits**: `<type>(<scope>): <subject>` —
  `type ∈ {feat, fix, docs, test, refactor, chore, ci}`. Scope is a
  crate or module name (e.g. `crypto`, `consensus`, `rpc`, `ops/faucet`).
- Branches: `feat/<feature-id>`, `fix/<issue-id>`, `docs/<topic>`,
  `chore/<topic>`, `release/v<version>`.
- Commit messages and code comments are **English**. PR/Issue
  descriptions may be Chinese.
- AI-authored commits include a `Co-authored-by: Copilot
  <223556219+Copilot@users.noreply.github.com>` trailer; AI-authored
  PR/Issue bodies start with `🤖 本 [Issue/PR] 由 AI Agent 创建`
  (literal template — do not translate).

## Things to never commit

Secrets, private keys, `*.keystore.json`, keystore password files, `.env`,
local node data (`/opt/shell/...`), `testnet-backup-*/`, any generated
runtime artifact.

## Tool pointers (this file is the SSoT)

- `CLAUDE.md` → read this file
- `.cursor/rules/main.mdc` → read this file
- `.github/copilot-instructions.md` → read this file
