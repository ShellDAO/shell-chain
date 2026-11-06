# Complete ML-DSA-65 verification equation

This development component proves all six rows and all 256 coordinates of
`Ahat * NTT(z) - NTT(c) * NTT(2^13 * t1)` in canonical ordinary residues modulo
8380417. Every coordinate includes all five matrix products and its subtractive
challenge product. These are the inputs to the inverse NTT producing `w_approx`
in [FIPS 204 Algorithm 8, step 9](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
August 13, 2024. Montgomery representation is not used at this interface.

`EquationInputs` contains the 30 row-major matrix polynomials, five transformed
z polynomials, the transformed challenge and six transformed scaled-t1
polynomials. Each polynomial has exactly 256 canonical coefficients.
`EquationProof` version 1 binds those operands and all six output polynomials.
The verifier checks the actual AIR, not a native matrix multiplication.

## Modular equation AIR

For each coordinate, add q^2 to the signed numerator:

```text
sum(Ahat[row,col,i] * zhat[col,i], col=0..4)
    + q^2 - chat[i] * that[row,i] = output[row,i] + q * quotient
```

The added multiple leaves the residue unchanged and makes the numerator
positive. Canonical public operands bound it below 6*q^2. The private quotient
is bounded to 0 through 6*q-1 with a 26-bit decomposition and a second 26-bit
decomposition of its complement. Boolean constraints prevent base-field
solutions with a noninteger or noncanonical quotient. The canonical output
then uniquely determines the required residue. All integer quantities are far
below the underlying proof field modulus, so bounded equality cannot wrap in
that field.

The AIR has 66 columns and 55 constraints of degree at most two. Thirteen public
operand/output columns have fixed even-row sequence assertions. There are 1536
real equations in a 4096-row trace; remaining slots are constrained zero
equations with quotient q. Only the final unused odd row has statement-derived
padding. The statement domain is `MLEQ0001`. Public inputs/results undergo exact
shape and canonical-domain checks; private quotient bounds are proved in AIR.
Only the prover computes native products to construct its witness. Verification
performs fixed routing, boundary assertions and real STARK verification.

## Source workflow

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), its
stable Rust toolchain and locked dependencies. First create a complete matrix
with the [existing matrix example](mldsa-matrix-proof.md). This can take tens of
minutes and supports verified coordinate checkpoints. Keep its directory for
reuse:

```bash
cargo run -p shell-stark-prover --example mldsa-matrix -- prove matrix-dir
cargo run -p shell-stark-prover --example mldsa-equation -- prove matrix-dir equation-dir
cargo run -p shell-stark-prover --example mldsa-equation -- verify matrix-dir equation-dir
```

The equation directory must be outside the matrix directory. Existing matrix
files are read and verified without regeneration or writes. Both directories
are required for independent verification; no saved personal keys, node,
account or funds are needed. The matrix example creates a temporary signed
public identity, with the private key retained only in memory.

The equation workflow binds the actual public key and raw signature to their
encoding proofs, then verifies all 30 coordinate proofs against the decoded
rho. A real SHAKE256/SampleInBall proof binds the challenge to the decoded
signature commitment. Twelve complete forward-NTT certificates bind all five
decoded z polynomials, all six decoded t1 polynomials scaled by 8192 and the
canonical challenge. The equation AIR consumes those exact authenticated
outputs. Six [inverse certificates](mldsa-inverse-proof.md) bind all 1536 result
coefficients to their canonical inverse outputs.

There are 22 component proof files plus a copy of the public identity in the
equation directory. Missing files are generated only in `prove` mode. Each is
created without overwriting an existing file, buffered, flushed, synced,
reloaded and cryptographically verified before use. Existing checkpoints are
reverified and reused. `verify` generates nothing and fails on missing or
invalid files. A partial directory is not a completed pipeline. Retain failed
files for inspection; interrupted partial-write recovery is unqualified.

The commands report counts and the first coefficients of each `w_approx` row
only after all components pass. Failures return a nonzero exit code. Rust's
reader preserves unsigned 64-bit permutation lanes. Bound untrusted JSON before
parsing. Native signature verification, streaming sampling, signed-integer
matrix arithmetic and direct inverse interpolation are independent controls;
they never replace a required proof.

## Scope and design decision

Status: accepted for this standalone developer component. Use one bounded
quotient for the full five-product sum and subtractive product, reusing the
existing backend and child formats. This avoids separate product-carry traces
while proving the same complete canonical equation. A valid child certificate
cannot substitute for a different row, key, signature, challenge or operand.

Intermediate states remain public and artifacts are not compact. This workflow
ends at `w_approx`. It does not yet constrain UseHint, the z norm, w1 encoding or
the final commitment hash comparison. Native signature control is not full
signature verification inside the AIR. Canonical-source/private-witness links,
actual node generation/admission/settlement/persistence/import/replay/rollback,
activation, fees and network resource acceptance remain unfinished. There is no
new consensus carrier, recursive backend, gas rule or activation height. Other
parameter sets and platform combinations remain unqualified.

## Focused regressions

```bash
cargo test -p shell-stark-prover mldsa_equation -- --nocapture --test-threads=1
```

Checks cover mixed, zero, maximum, negative-numerator and sparse last-coordinate
inputs against independent signed arithmetic; all rows and all five products;
real mixed/zero proofs and JSON; term/result changes; canonical shapes, versions,
payloads and foreign layouts. A forged private quotient satisfies the modular
and reconstruction equalities using proof-field inversion but fails Boolean
bounds, exercising the distinction between the proof field and the ML-DSA field.
Full dataflow acceptance is separately exercised through the public workflow,
including independent verification of persisted component files.
