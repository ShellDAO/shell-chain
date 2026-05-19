# Contributing to Shell-Chain

Thank you for considering contributing to Shell-Chain! Below are the guidelines for participation.

## Development Environment

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- C compiler (required for pqcrypto native bindings)
- Git

### Initialization

```bash
git clone https://github.com/LucienSong/shell-chain.git
cd shell-chain
cargo build
cargo test
```

## Development Process

We use the **Feature-Driven Development (FDD)** methodology. Every feature is organized as a distinct Feature unit.

### Branch Strategy

| Branch | Purpose |
|------|------|
| `main` | Stable release branch, protected |
| `feat/<feature-id>` | Feature development branch |
| `fix/<issue-id>` | Bug fix branch |

### Commit Standards

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(primitives): add BLAKE3 hash function
fix(crypto): zeroize secret key on drop
docs(readme): update crate status table
test(core): add block RLP roundtrip test
refactor(core): split Signer into Signer + Verifier
```

Format: `<type>(<scope>): <description>`

**Type**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`
**Scope**: Crate name or module (`primitives`, `crypto`, `core`, `storage`, etc.)

### Pull Request Flow

1. Create a feature branch from `main`
2. Implement the feature and ensure all tests pass
3. Submit a PR and fill out the template
4. Wait for Code Review
5. Delete the feature branch after merging

## Code Conventions

### Rust Style

- Follow default `rustfmt` configurations
- Adhere to `clippy` suggestions (`cargo clippy --workspace`)
- Public APIs must have documentation comments (`///`)
- Avoid redundant comments; code should be self-explanatory

### Testing

- Each module must include unit tests (`#[cfg(test)] mod tests`)
- Integration tests belong in the `tests/` directory
- New features must include test coverage
- Run all tests: `cargo test --workspace`

### Security Standards

- Private key material must use `zeroize` to ensure wiping upon drop
- Do not introduce non-quantum-safe cryptographic primitives (unless explicitly marked as a deprecated compatibility layer)
- Signature verification code must include negative tests (e.g., invalid signature, mismatched public key)

## Architecture Overview

```text
shell-primitives  ←  shell-crypto  ←  shell-core
       ↑                  ↑               ↑
       └──────────────────┼───────────────┤
                          │         ┌─────┴──────┐
                       storage    evm    consensus
                          │        │         │
                       network ← mempool     │
                          │                  │
                        node ← rpc ──────────┘
```

For detailed designs, refer to the [docs/](docs/) directory in this repository.

## Reporting Issues

Use [GitHub Issues](https://github.com/LucienSong/shell-chain/issues) and include:

- A clear description of the issue
- Steps to reproduce
- Expected vs. actual behavior
- Rust version and operating system

## License

Contributed code will be released under the [MIT License](LICENSE).
