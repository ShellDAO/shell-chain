# Getting Started

> Quickstart guide for understanding and contributing to `shell-chain`.

## Current Status

`shell-chain` is currently a **docs-first repository**.
It does not yet include a Rust workspace, `Cargo.toml`, or runnable crates, so there is nothing to build with Cargo today.
The current repository milestone is to make the local implementation specs detailed enough that the first Rust scaffold can follow them directly.

## What You Can Do Today

You can use this repository to:

1. understand the planned architecture,
2. review the local implementation specs,
3. refine documentation before code lands,
4. prepare future crate scaffolding against documented boundaries.

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

This layout is a plan, not an already-scaffolded workspace.

## Build, Test, and Lint Expectations

There are currently no repository-local Cargo commands to run because the workspace has not been created yet.
If you are contributing documentation only, the main sanity check is to keep terminology, links, and stated repository status accurate.

The four core specs in `specs/` are currently all `draft` documents rather than stubs. They are already detailed enough to drive initial implementation planning while still clearly labeling any remaining pending-closure items.

If you introduce initial Rust scaffolding in the future, that change should also add and document the exact local commands for:

- building,
- testing,
- formatting,
- linting,
- and generating API documentation.

## First Contribution Checklist

Before opening a change, confirm that:

- the explanation is self-contained inside this repository,
- planned components are clearly labeled as planned,
- current repository limitations are stated honestly,
- and docs remain aligned with the implementation specs.
