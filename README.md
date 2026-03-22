# shell-chain

> A docs-first Rust implementation repository for the Shell blockchain protocol.
> The focus today is on making the design, interfaces, and implementation boundaries clear before code scaffolding begins.

## Current Status

`shell-chain` is still primarily a documentation-and-specification repository, but it now also includes a **minimal Rust workspace bootstrap**.
The repository has a root `Cargo.toml`, a working `shell-primitives` crate, early `shell-crypto` and `shell-state` interface crates, and shared fixtures under `vectors/`.
It does **not** yet provide a runnable node, a full crate tree, or a production-ready implementation of the protocol.

At this stage, the core implementation specs in `specs/` are all at **draft** status and are intended to be detailed enough to drive initial implementation planning, including crate scaffolding, fixture planning, and validation/interface placement.

## shell-chain in One Page

The planned implementation centers on a few protocol ideas that shape every crate and API boundary:

- **Post-quantum-first authorization**: account and validator signing paths are designed around post-quantum-capable (PQ) signature schemes instead of legacy ECDSA assumptions.
- **Witness separation**: executable transaction envelopes stay separate from large cryptographic witness sidecars, meaning the heavier proof bundle travels alongside the core object instead of being folded into it.
- **Dual-lane fee accounting**: normal execution pricing and witness-heavy pricing are tracked separately so expensive proof bandwidth does not hide inside one fee number.
- **SSZ-first data model**: wire-facing objects are expected to keep canonical SSZ (SimpleSerialize) encoding and merkleization behavior.
- **Stateless-friendly validation**: transaction admission, block import, and proof reconstruction are split into stages so light and full validation paths can share the same object model.
- **Unified binary-tree state**: the state layer is intended to use a compressed binary-tree accumulator rather than a legacy fixed-depth sparse tree.

## Repository Layout

| Path | Purpose |
|---|---|
| `README.md` | High-level repository overview and current status |
| `docs/` | Reader-friendly guides for onboarding, API expectations, and contribution workflow |
| `specs/` | Implementation specifications for data types, validation flow, testing vectors, and planned module boundaries |

## Planned Workspace Shape

The crate layout below describes the intended full architecture. Today, `shell-primitives`, `shell-crypto`, and `shell-state` are scaffolded in the workspace, while the remaining crates are still placeholders:

- `shell-primitives`: SSZ-facing types, roots, aliases, and canonical codec helpers
- `shell-crypto`: signature dispatch, hashing boundaries, and scheme-specific verification adapters
- `shell-state`: state-key modeling, witness verification, and accumulator abstractions
- `shell-execution`: execution-layer transition logic and post-state output calculation
- `shell-mempool`: transaction admission, fee-floor checks, and cheap-first screening
- `shell-consensus`: block-level binding, header/body checks, and import orchestration
- `shell-network`: peer-facing propagation, fetch policy, and reputation consequences
- `shell-cli`: operator entry points, configuration, and RPC surface

## Documentation Map

After this overview, continue through the repository in this order:

1. `docs/getting-started.md` for the onboarding path and brief terminology orientation.
2. `docs/api-reference.md` for the planned public API surface and stability expectations.
3. `specs/README.md` for the implementation-spec index.

### Recommended Spec Reading Order

From there, continue through the core specs in this order:

1. `specs/crate-structure.md`
2. `specs/data-types.md`
3. `specs/validation-rules.md`
4. `specs/testing-vectors.md`

When you are ready to make a repository change, continue with `docs/contributing.md`.

## Build and Test Status

A minimal Rust workspace is now scaffolded with `shell-primitives` plus early `shell-crypto` and `shell-state` interfaces. The repository-local bootstrap commands are:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

The remaining planned crates under `crates/` are still directory placeholders until their crate-specific scaffolding is introduced. The documentation set in `specs/` remains the source of truth for open protocol areas and for behavior that the current bootstrap intentionally keeps abstract.
