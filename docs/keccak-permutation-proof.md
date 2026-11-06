# Keccak-f1600 permutation proof

This development source example proves one complete Keccak-f1600 permutation:
all 1600 bits and all 24 rounds, including theta, rho, pi, chi and iota. It is a
component for the full post-quantum signature verification target. SHAKE
padding, absorption, squeezing, ML-DSA verification and node settlement remain
unfinished. The example is not a released node command or an activated protocol
feature.

The specification is [FIPS 202, sections 3.1–3.4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
August 2015. Lanes use index `x + 5*y`; bit zero is the least significant bit of a
little-endian 64-bit lane. All 25 input lanes are accepted, including zero and
all-one states. Independent full-state known answers come from the
[XKCP permutation vectors](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt).
This implementation is not a NIST-validated cryptographic module.

## Run the source example

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), the
repository's stable Rust toolchain, and its locked dependencies. No running node,
account, funds or saved keys are needed. Run from the repository root:

```bash
cargo run -p shell-stark-prover --example keccak-permutation -- prove permutation.json
cargo run -p shell-stark-prover --example keccak-permutation -- verify permutation.json
```

`prove` generates a real Winterfell proof, checks it, writes a new JSON file,
syncs the file and verifies the reloaded contents. It refuses to overwrite an
existing file. `verify` loads the existing artifact in a separate process and
checks it without generating another proof. Failure returns a nonzero exit code.

The artifact includes a public example message, the full expected output, all
public round states and the proof. The example computes a single SHAKE256 input
block using native padding, checks the permutation AIR, and compares the first
136 output bytes with the independent native SHAKE256 implementation. That
native comparison is a control; the sponge and padding are not AIR-constrained.
The full 200-byte permutation output is checked against independent known
answers in the focused tests. This example accepts messages shorter than 136
bytes and does not claim multi-block hashing or extended squeezing.

## What the AIR establishes

The trace has 112 columns and 4096 rows. Each real even row handles one bit
position of one round: 24 rounds times 64 positions. It constrains five column
parities, 25 theta updates and 25 chi/iota outputs using 55 polynomial
constraints of degree at most six. All real rows, including the last round's
highest bit, have fixed sequence boundary assertions. Padding slots are fixed;
only the final unused odd row carries statement-derived trace padding.

Every lane bit, parity bit, rotated source bit and round constant on an operation
row is bound by public boundary assertions. Booleanity follows from those
assertions: each asserted value is a bit extracted from a typed `u64`. Rho/pi
routing reads the corresponding bit of the same public theta lane at its fixed
rotation offset; theta parity routing similarly binds the previous bit with
wraparound. Each round output is reused as the next round input. The verifier
performs bit extraction and fixed routing, then real STARK verification; it does
not execute a native permutation or hash to replace these constraints.

The `KeccakPermutationProof` version is 1, with a distinct `KECF1601` public-input
domain. `verify_keccak_permutation` takes the expected 25-lane input and final
output independently from the caller. It rejects wrong endpoints, a round count
other than 24, unexpected trace layout, unacceptable proof options, empty or
larger-than-1-MiB proof payloads, and invalid proofs. Applications remain
responsible for authenticating the expected endpoints and for limiting the size
of untrusted JSON before parsing.

All intermediate parity, theta and round output lanes are public. This design
neither hides data nor provides a compact hash attestation. It does not prove
possession of a key, signature validity, or correspondence with a canonical
transaction. It is separate from existing signature-batch proof formats and
leaves admission, block import, replay and activation behavior unchanged.

## Regression entry

```bash
cargo test -p shell-stark-prover keccak_permutation -- --nocapture
```

Coverage includes real proofs for zero and all-one states, JSON reload, two
published full-state permutation vectors, an independent bit-array reference,
round constant generation, native SHAKE256 controls at the one-block rate edge,
all round/bit residuals, and rejection of changed parity, theta, intermediate and
final output, high input bits, malformed shapes, versions, proof payloads and
foreign trace layouts. These are component checks; they do not complete the
full PQ signature verification or node workflow acceptance.
