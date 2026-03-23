# Contributing to shell-chain

## Current Development Mode

`shell-chain` is in a docs-first phase with an early Rust workspace bootstrap.
Contributions today primarily improve repository-local understanding while extending the bootstrap carefully: architecture notes, implementation specs, onboarding guidance, fixtures, and low-risk foundational crate work.

## Core Expectations

- Keep documentation self-contained inside this repository.
- Label planned components as planned; do not imply that missing crates, binaries, or Cargo workflows already exist.
- Prefer clarifying local architecture and interfaces before proposing large implementation changes.
- Keep all prose, comments, identifiers, and filenames in English.

## What Good Contributions Look Like

Useful contributions at the current stage include:

- clarifying the planned crate boundaries,
- tightening the API and validation docs,
- removing ambiguity from terminology,
- aligning docs with the local implementation specs,
- extending the initial workspace bootstrap only when the supporting docs are updated at the same time.

## Workflow

1. Create a branch for your change.
2. Update the relevant local docs and specs first.
3. Keep cross-file terminology consistent.
4. If you add code scaffolding, add or update the corresponding repository-local build/test instructions in the same change.
5. Open a pull request with a clear explanation of what changed and why.

## Expectations for Future Code Changes

With the current workspace bootstrap in place, code changes should also:

- pass the repository's documented format, lint, and test commands,
- include doc comments for public items where appropriate,
- avoid unnecessary `.unwrap()` usage in production paths,
- preserve the crate boundaries described in the local specs unless the specs are updated deliberately.

At the moment, contributors can rely on `cargo fmt --all`, `cargo check --workspace`, and `cargo test --workspace`. Do not claim that stronger commands such as `cargo clippy` or generated API docs are available unless they are added locally in the same change.

## Review Guidance

Reviewers should check that a contribution:

- improves local clarity,
- keeps the repository self-contained,
- does not overstate implementation maturity,
- and stays consistent with the docs-first direction of the project.

## Commit Messages

Use a clear, imperative summary that explains the user-visible or contributor-visible change.
Examples:

- `Clarify validation pipeline terminology`
- `Document planned crate boundaries`
- `Add initial workspace scaffold`
