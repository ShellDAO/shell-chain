# Getting Started

> Quickstart guide for understanding and contributing to `shell-chain`.

## Current Status

`shell-chain` is currently a **docs-first repository**.
It now includes a **minimal Rust workspace bootstrap** with `shell-primitives` and early `shell-crypto` / `shell-state` interface crates.
It still does not provide a runnable node or a fully scaffolded crate tree, so the current repository milestone is to extend that bootstrap carefully from the documented specs.

## What You Can Do Today

You can use this repository to:

1. understand the planned architecture,
2. review the local implementation specs,
3. run the current bootstrap checks,
4. refine documentation and early code together against documented boundaries.

If terms like SSZ, witness sidecars, or PQ authorization are new, read them here as shorthand for canonical SimpleSerialize encoding, proof-heavy side data kept separate from core envelopes, and post-quantum-capable signature handling.

## Recommended Reading Path

If you are starting fresh, use the repository in this order:

1. `README.md` for the project overview and status
2. `docs/getting-started.md` (this guide) for onboarding and terminology
3. `docs/api-reference.md` for the planned public API boundaries
4. `specs/README.md` for the implementation-spec index
5. `specs/crate-structure.md` for workspace and dependency boundaries
6. `specs/data-types.md` for the Rust-facing object model
7. `specs/validation-rules.md` for runtime flow and failure handling
8. `specs/testing-vectors.md` for fixture planning and invariant ownership

When you are ready to turn that context into a change, continue with `docs/contributing.md`.

## Planned Workspace Overview

The intended workspace is organized around clear domain boundaries:

- **`shell-primitives`** for SSZ-facing types, roots, and canonical codec helpers
- **`shell-crypto`** for hashing and signature-dispatch abstractions
- **`shell-state`** for witnesses, state keys, and accumulator verification
- **`shell-execution`** for state-transition execution logic
- **`shell-mempool`** for transaction admission and fee-policy checks
- **`shell-consensus`** for block assembly/import orchestration
- **`shell-network`** for propagation, fetch policy, and peer consequences
- **`shell-cli`** for operator-facing entry points and RPC wiring

This layout is still the full plan, not a statement that every crate is implemented today. Right now the workspace bootstrap covers `shell-primitives` plus early `shell-crypto` and `shell-state` scaffolding.

## Build, Test, and Lint Expectations

The current repository-local bootstrap commands are:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

If you are contributing documentation only, the main sanity check is still to keep terminology, links, and stated repository status accurate.

The four core specs in `specs/` are currently all `draft` documents rather than stubs. They are already detailed enough to drive the current workspace bootstrap while still clearly labeling any remaining pending-closure items.

As the workspace expands, changes should also keep these commands accurate and add new ones only when they actually exist locally.

## First Contribution Checklist

Before opening a change, confirm that:

- the explanation is self-contained inside this repository,
- planned components are clearly labeled as planned,
- current repository limitations are stated honestly,
- and docs remain aligned with the implementation specs.
