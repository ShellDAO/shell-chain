# Contributing to shell-chain

## Status: STUB

## Code Standards

- All code must pass `cargo clippy -- -D warnings` and `cargo fmt --check`.
- All public items must have `///` doc comments.
- Avoid `.unwrap()` in production code; use `Result<T, E>`.

## Workflow

1. Fork and create a feature branch.
2. Make changes following the coding standards above.
3. Run `cargo test` and `cargo clippy` locally.
4. Submit a pull request with a clear description.

## Commit Convention

> TODO: Define commit message convention (e.g., Conventional Commits).

## Review Process

> TODO: Define the code review process and approval requirements.
