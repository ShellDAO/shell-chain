# Getting Started

> Quickstart guide for understanding and contributing to `shell-chain`.

## Current Status

`shell-chain` is currently a **docs-first repository**.
It does not yet include a Rust workspace, `Cargo.toml`, or runnable crates, so there is nothing to build with Cargo today.

## What You Can Do Today

You can use this repository to:

1. understand the planned architecture,
2. review the local implementation specs,
3. refine documentation before code lands,
4. prepare future crate scaffolding against documented boundaries.

## Recommended Reading Path

If you are starting fresh, read the repository in this order:

1. `README.md` for the project overview and status
2. `docs/api-reference.md` for the planned public API boundaries
3. `specs/README.md` for the implementation-spec index
4. `specs/data-types.md` and `specs/validation-rules.md` for the most concrete current design details

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
