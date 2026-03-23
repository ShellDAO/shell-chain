# Rust and Cryptography Review Guidelines

## Introduction
These guidelines are designed to help contributors ensure that code related to Rust and cryptography meets the highest standards of quality, security, and performance.

## General Guidelines
1. **Code Clarity**: Write clear and concise code. Use meaningful variable and function names.
2. **Documentation**: Provide comprehensive documentation for all public functions and structures, especially those dealing with cryptography.
3. **Testing**: Ensure all code is well-tested with unit tests and integration tests. Use the `cargo test` command to run tests.
4. **Error Handling**: Implement proper error handling. Use `Result<T, E>` types for functions that can fail.

## Rust-Specific Guidelines
1. **Ownership and Borrowing**: Familiarize yourself with Rust’s ownership model. Avoid unnecessary clones to improve performance.
2. **Concurrency**: Make use of Rust's concurrency features when dealing with multi-threaded applications. Use the `std::sync` module appropriately.
3. **Unsafe Code**: Limit the use of `unsafe` blocks. Document why it is necessary if used.

## Cryptography-Specific Guidelines
1. **Use Standard Libraries**: Whenever possible, use established cryptographic libraries from the [RustCrypto](https://github.com/RustCrypto) crate family (e.g., `sha2`, `aes`, `ed25519-dalek`) or `ring` instead of implementing your own cryptographic functions. Avoid the unmaintained `rust-crypto` crate — use the actively-maintained `RustCrypto` ecosystem instead. The project already uses `ed25519-dalek` for digital signatures.
2. **Security Practices**: Follow best practices for cryptographic implementations:
   - Use established algorithms with good security properties.
   - Avoid using obsolete algorithms such as MD5 and SHA-1.
   - Regularly update dependencies and apply security patches.
3. **Randomness**: Use secure random number generators provided by the `rand` crate. Avoid using `rand::random()` in security-sensitive contexts.

## Dependency Pinning

Cryptographic dependencies should be pinned to specific versions to ensure reproducible builds and avoid unexpected breakage from upstream changes.

- Pin cryptographic crate versions in `Cargo.toml` (e.g., `ed25519-dalek = "2.1.1"` rather than `ed25519-dalek = "2"`).
- Run `cargo audit` regularly to check for known vulnerabilities in dependencies. This is also enforced automatically on every PR via the GitHub Actions workflow (`.github/workflows/pr-review.yml`).
- Review and update dependency versions deliberately, especially for security-sensitive crates.

## Review Process
1. **Peer Review**: All cryptographic code must undergo peer review.
2. **Automated Tools**: Utilize automated tools like Clippy and Rustfmt for linting and formatting.
3. **Security Audits**: For critical components, consider third-party security audits.

## Conclusion
By adhering to these guidelines, we can maintain high standards for Rust and cryptography code within the ShellDAO shell-chain repository. 

---

_Last updated: 2026-03-23_