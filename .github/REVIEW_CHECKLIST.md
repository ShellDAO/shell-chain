# PR Review Checklist

This document outlines the comprehensive checklist for reviewing pull requests to ensure high standards of quality across various aspects of the codebase.

## 1. Code Quality
- [ ] Code follows style guidelines (consistent naming conventions, formatting).
- [ ] No unused variables or imports.
- [ ] Code complexity is manageable and broken into functions/methods where needed.
- [ ] No obvious performance bottlenecks.

## 2. Documentation
- [ ] Code is adequately documented (comments for complex logic).
- [ ] External documentation is updated (README, API docs).
- [ ] All public-facing functions/modules have corresponding doc comments.

## 3. Rust Best Practices
- [ ] Use of idiomatic Rust constructs (e.g., ownership, borrowing)._ 
- [ ] Proper error handling practices.
- [ ] Avoiding unnecessary clones or references.
- [ ] Utilization of Rust's powerful type system effectively.

## 4. Cryptography Review
- [ ] Review cryptographic algorithms used in the implementation.
- [ ] Ensure compliance with current cryptography standards.
- [ ] All sensitive data is handled securely (e.g., using proper libraries).

## 5. Workspace Configuration
- [ ] Ensure proper setup of `Cargo workspaces` for multi-package repositories.
- [ ] Validate that all project dependencies are listed correctly in `Cargo.toml`.
- [ ] Check for any required environment variables or configurations.

## 6. Testing Requirements
- [ ] Unit tests cover a significant portion of the new code.
- [ ] Integration tests are written where necessary.
- [ ] Review performance tests if applicable.
- [ ] Ensure that tests can run in the CI/CD pipeline without issues.

## 7. Commit Message Standards
- [ ] Commit messages follow the conventional format (e.g., `feat:`, `fix:`, `chore:`).
- [ ] Each commit message is clear and explains the purpose of the change.
- [ ] For multiple commits, ensure they are squashed into a single coherent commit where applicable.

## 8. Cargo.toml Validation
- [ ] Dependencies are up-to-date and specified with the correct versions.
- [ ] Package metadata is correctly filled out (name, version, author).
- [ ] Ensure compatibility settings are verified (e.g., Rust edition).

---

_Last updated on: 2026-03-22 09:53:20 UTC_  
