# ML-DSA-65 matrix expansion proofs

This development source component proves `RejNTTPoly` and complete `ExpandA`
coverage for ML-DSA-65. Each polynomial is bound to its public 32-byte `rho` and
matrix coordinate through `SHAKE128(rho || column || row)`. A complete matrix
contains all 30 polynomials in row-major order: six rows, five columns and 256
coefficients per polynomial, already in NTT representation.

The specification is [FIPS 204, Algorithms 14, 30, 32 and Table 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
August 13, 2024. The modulus is 8380417. This composes the sampler AIR with the
[SHAKE sponge and complete permutation proofs](shake-sponge-proof.md). All raw
XOF bytes, counters, coefficients and permutation states are public. Private
witnesses, compact aggregation, the complete signature equation and actual node
settlement remain unfinished. This is not a NIST-validated module or a released
node CLI.

## Source entry

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), the
repository's stable Rust toolchain and locked dependencies. From the repository
root:

```bash
cargo run -p shell-stark-prover --example mldsa-matrix -- prove matrix-dir
cargo run -p shell-stark-prover --example mldsa-matrix -- verify matrix-dir
```

No node, funds, account or saved keys are required. A new directory gets an
`identity.json` containing a temporary ML-DSA-65 public key, public message and
signature. The private key stays in memory and is not written or printed.
The first 32 public-key bytes supply `rho`.

Proving a complete matrix can take tens of minutes. Each coordinate is stored
separately as `a-row-column.json`, synced, reloaded and checked against an
independent streaming native oracle and the real proof chain. A resumed `prove`
rechecks existing files and proves only missing coordinates. Existing files are
not overwritten; an invalid file causes an error. The final `verify` command
loads all 30 files in a separate process without generating proofs, checks the
entire coordinate coverage and compares every one of the 7680 coefficients with
the independent oracle. Failures return a nonzero exit code.

To bound new work per invocation, pass a count from 1 through 30:

```bash
cargo run -p shell-stark-prover --example mldsa-matrix -- prove matrix-resume-dir 1
cargo run -p shell-stark-prover --example mldsa-matrix -- prove matrix-resume-dir
cargo run -p shell-stark-prover --example mldsa-matrix -- verify matrix-resume-dir
```

The first invocation produces a partial checkpoint and reports
`full_matrix_verified: false`. Running `verify` at that point must fail because
29 coordinates are missing. The next invocation reuses the saved valid proof and
continues the remaining coordinates. Only complete coverage reports
`full_matrix_verified: true`. Recovery of completed, synced checkpoints is the
supported scenario; power-loss and interrupted partial-file recovery are not
established by these checks. Keep the directory intact for inspection if a write
or verification fails.

The native signature and matrix calculations are independent controls. This
example does not prove signature validity inside the AIR or authenticate a
canonical transaction source. Applications must authenticate the expected `rho`
and expected output matrix, and bound untrusted JSON before parsing. SHAKE state
lanes use unsigned 64-bit values; the Rust reader preserves them exactly.

## Masking, rejection and output constraints

The sampler consumes each consecutive three-byte candidate. It reconstructs the
third byte from seven low bits and its high bit, excludes that high bit from the
23-bit candidate, and accepts exactly the values below the modulus. Equality to
the modulus is rejected. A 23-bit difference and Boolean acceptance flag prove
both directions of that comparison. An eight-bit slack bounds the accepted
counter before each attempt to 0 through 255. The counter starts at zero, ends at
256, advances only on acceptance, and cannot consume extra candidates after the
final coefficient. Accepted values bind the corresponding output position.

The AIR has 47 columns and 45 constraints with maximum degree three. Seven fixed
even-row sequence assertions bind raw bytes, counters and the selected output
coefficient. Forty private Boolean columns establish acceptance, seven low bits,
the high bit, the 23-bit difference and eight-bit counter slack. No native
coefficient range filter substitutes for the AIR. Only the final unused odd row
carries statement-derived trace padding. The normal 256/257-attempt cases use
512/1024 trace rows; the bounded maximum can reach 4096 rows.

`MatrixPolynomialProof` version is 1, with statement domain `MLMATR01`.
`verify_matrix_polynomial` requires the expected `rho`, row, column and all 256
coefficients from the caller. The verifier performs fixed routing and real
sampler, SHAKE and permutation verification. It does not evaluate native SHAKE,
mask candidates or perform native rejection sampling to replace the proofs.
`MatrixProof` version 1 combines all 30 polynomials; `verify_matrix` requires exact
row-major coordinate coverage, rejecting partial, duplicate, reordered or
foreign-coordinate data.

The prover begins with 840 XOF bytes and expands up to the existing 4096-byte
SHAKE development limit if needed. It returns a resource error if that cannot
produce 256 accepted coefficients. Every SHAKE permutation is fully proved.
These development limits do not set consensus gas, fees or network validation
rules. Exceptional real seeds needing expansion and the maximum-size sampler
trace remain unqualified unless explicitly exercised. Other ML-DSA parameter
sets and full node import, replay, rollback and activation acceptance remain open.

## Design decision

Status: accepted for this development component.

Reuse the existing Winterfell backend and SHAKE proof format. Keep the sampling
stream and accepted counter public, constrain masking/comparison/output relations
inside the AIR, and compose one proof per fixed matrix coordinate. Completed
coordinate files provide incremental progress and allow verified reuse across
invocations. This increases artifact size and verification work; it adds no
recursive backend or network proof carrier.

## Focused regressions

```bash
cargo test -p shell-stark-prover mldsa_matrix -- --nocapture --test-threads=1
```

Real proofs cover zero-`rho` coordinate `(0,0)` with a rejection and all-`ff`
`rho` coordinate `(5,4)` without rejections. All coefficients match an independent
streaming implementation; fixed prefixes also match Python hashlib/OpenSSL.
Synthetic rows cover 0, q-1, q, the maximum 23-bit value, high-bit masking and
counter boundaries. Forged q acceptance and a wrong high-bit mask satisfy linear
equalities but fail Boolean constraints. Short counter sequences are rejected before trace construction. Further checks reject changed
coordinates/counters/output/stream, malformed layouts and payloads, and corrupted
inner SHAKE/Keccak proofs. Full 6x5 acceptance is separately exercised through the
complete source example; a scalar proof or partial checkpoint cannot establish
it.
