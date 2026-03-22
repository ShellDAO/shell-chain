# shell-chain

> A docs-first Rust implementation repository for the Shell blockchain protocol.
> The focus today is on making the design, interfaces, and implementation boundaries clear before code scaffolding begins.

## Current Status

`shell-chain` is currently a documentation and specification repository.
There is **no Rust workspace, no `Cargo.toml`, and no buildable crate tree checked in yet**.
The repository exists to capture the implementation plan in a self-contained way so future code can be added against stable local documentation.

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

The crate layout below is **planned architecture**, not a statement that these crates already exist in the repository:

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

Because the Rust workspace has not been scaffolded yet, repository-local commands such as `cargo build`, `cargo test`, `cargo clippy`, and `cargo doc` are **not available yet**.

Today, the repository's primary source of truth is the local documentation set. When code scaffolding is added, the build and test instructions should be added here and kept fully local to this repository.
