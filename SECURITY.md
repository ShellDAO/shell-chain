# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | ✅ Active |
| v0.24.x | ✅ Security fixes |
| < v0.24.0 | ❌ End of life |

**v0.24.x is the current supported release line.** `main` receives active development and security fixes; v0.24.x receives security-only backports. Users on versions older than v0.24.0 should upgrade before reporting issues against them.

## Scope

The following components are **in scope**:

- `crates/crypto` — PQ signature stack (ML-DSA-65, Dilithium3, SPHINCS+), PQ-HD v1 key derivation
- `crates/keystore` — Argon2id + XChaCha20-Poly1305 HD seed encryption
- `crates/consensus` — wPoA engine, validator set, slashing conditions
- `crates/pqvm` — PQVM execution adapter, parallel scheduler
- `crates/node` — NodeBuilder, AA transaction processing, system_rewards
- `crates/rpc` — JSON-RPC handler, TLS, three-RPC fanout
- `crates/mempool` — transaction pool, AA validation
- `crates/stark-prover` — STARK settlement
- `crates/cli` — `shell-chain` binary, `pqhd` key management commands
- Protocol-level vulnerabilities (consensus safety/liveness, double-spend, AA bypass)
- Denial-of-service attacks that can halt block production on the public testnet

The following are **out of scope**:

- Issues requiring physical access to validator hardware
- Social engineering of maintainers
- Bugs in third-party dependencies (report those upstream; note the dependency here)
- Testnet funds — the testnet carries no real value
- Known limitations documented in `CHANGELOG.md` or open GitHub issues

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred channel — GitHub Private Security Advisories

1. Go to **[Security → Advisories](https://github.com/ShellDAO/shell-chain/security/advisories/new)**
2. Fill in the advisory form (affected versions, component, reproduction steps, impact)
3. Submit — this creates a private draft visible only to maintainers

### Alternative — encrypted email

If you prefer email, contact the maintainers at the address listed in
[`Cargo.toml`](./Cargo.toml) under `[package].authors`, or reach the ShellDAO
security team via the contact on [shell.org](https://shell.org).

We will acknowledge receipt within **72 hours** and aim to provide an initial
assessment within **7 days**.

Please include:
- A concise description of the vulnerability
- Affected component(s) and version(s)
- Step-by-step reproduction or proof-of-concept
- Potential impact and attack scenario
- Any suggested mitigations (optional)

## Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter submits vulnerability privately.
2. Maintainers confirm, assess severity, and develop a fix (target: ≤ 30 days for Critical/High, ≤ 90 days for Medium/Low).
3. A patched release is published.
4. A public GitHub Security Advisory is opened and CVE is requested if appropriate.
5. Reporter is credited in the advisory (unless they prefer anonymity).

We ask reporters not to publicly disclose details until a fix has been released,
or until 90 days have elapsed from initial report (whichever comes first).

## Severity Guidelines

We use the [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) scale as a
starting reference, adjusted for blockchain-specific context:

| Severity | Examples |
|----------|---------|
| **Critical** | Remote code execution on validator nodes; consensus safety break (double finalization); private key extraction from keystore; PQ-HD v1 seed leakage |
| **High** | Consensus liveness halt; AA bypass allowing unauthorized transaction execution; mempool DoS halting block production; STARK proof forgery |
| **Medium** | RPC information disclosure; nonce manipulation in mempool; side-channel leaking partial key material |
| **Low** | Minor information disclosure; cosmetic input validation gaps; non-exploitable panics in non-critical paths |

## Cryptographic Algorithms

Shell-Chain uses post-quantum cryptography exclusively for signing:

- **ML-DSA-65** (FIPS 204) — primary signing algorithm
- **Dilithium3** — legacy-compatible active path
- **SPHINCS+-SHA2-256f** — fallback signing algorithm
- **BLAKE3** — hashing and key derivation (PQ-HD v1)
- **Argon2id** — keystore KDF
- **XChaCha20-Poly1305** — keystore encryption

Vulnerabilities in the underlying PQC standards (ML-DSA, SPHINCS+) should be
reported to NIST and the relevant algorithm authors. Implementation-level
vulnerabilities in how Shell-Chain uses these primitives are in scope here.

## Bug Bounty

There is currently **no formal bug bounty program**. Researchers who report
valid Critical or High severity issues in good faith will be publicly credited
in the security advisory and in `CHANGELOG.md`.

## Security Hardening Notes

For operators running validator nodes, consult the
[Testnet Operator Guide](./docs/TESTNET_OPERATOR_GUIDE.md) and ensure:

- Keystores are stored with filesystem permissions `600`, owned by the node
  process user only
- The RPC/WS ports (`8545` HTTP JSON-RPC, `8546` WebSocket, `8548`/`8549` for
  rpc-node) are not exposed to the public internet without authentication/TLS
- The `pqhd` CLI reads mnemonics from stdin (no shell history exposure); never
  pass mnemonics as command-line arguments
- Backups of `*.keystore.json` files must be encrypted at rest
