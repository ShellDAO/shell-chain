# ML-DSA inverse NTT certificates

This development component proves the canonical inverse NTT of a public
256-coefficient polynomial modulo 8380417. It reuses the complete
[forward NTT AIR](mldsa-ntt-proof.md), including all 1024 butterflies,
fixed twiddles, public intermediate states and canonical modular reductions.
It introduces no second arithmetic AIR or separate inverse-stage trace.

The specification is [FIPS 204 §2.5 and Algorithms 41–42](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
August 13, 2024. Let F be its forward transform. For a supplied input x and
output y, the verifier checks the actual STARK proving F(y) = x. It does not
compute a native inverse or use a native arithmetic check instead of the AIR.

The 256 evaluation points are the distinct roots of X^256 + 1 in the prime
field. Consequently F is bijective, and F(y) = x uniquely forces every output
coefficient to be the normalized inverse. Explicitly, coefficient j equals
256^-1 times the sum of x[i] times root[i]^-j, modulo q; 256^-1 is 8347681.
Omitting that factor proves the relation for 256*x instead of x and fails the
original endpoints. The prover constructs its candidate using Algorithm 42,
with ascending butterfly widths and reversed, negated twiddles followed by
the inverse-256 factor. Independent direct interpolation checks its results.

## Source entry

Use the stable Rust toolchain and locked dependencies in a checkout of
[shell-chain](https://github.com/ShellDAO/shell-chain). From the repository root:

```bash
cargo run -p shell-stark-prover --example mldsa-inverse -- prove inverse.json
cargo run -p shell-stark-prover --example mldsa-inverse -- verify inverse.json
```

No node, funds or saved keys are needed. A new invocation generates a temporary
ML-DSA-65 key and signature. Only the public key, message and signature are saved;
the private key remains in memory. The public key's rho supplies matrix
coordinate (0,0). Its real SHAKE128, complete permutation and rejection-sampling
proofs bind all 256 NTT coefficients. The inverse certificate binds that exact
polynomial to its inverse, compared coefficient by coefficient with direct
interpolation. This exercises one coordinate; it does not claim a complete
6x5 matrix or the full signature verification equation.

The file is created without overwriting an existing artifact, synced, reloaded
and verified. The second command verifies the saved artifact in a separate
process without generating proofs. Errors return a nonzero exit code. Recovery
of interrupted partial writes is unqualified; retain a failed file for inspection.
Bound untrusted JSON before parsing. Rust preserves unsigned 64-bit state lanes.

## Format and integration boundary

`InverseNttProof` version 1 contains a `forward: NttProof`. Its inner format and
statement domain intentionally remain `MLNTT001`: this is reuse of the same
forward relation, with the expected endpoints reversed. A valid forward proof
is therefore a valid inverse certificate for its reversed endpoints. It cannot
establish unrelated endpoints or a different normalization. Callers must
authenticate both expected polynomials; the wrapper is not a new transcript
domain, signature proof or network carrier.

`prove_inverse_ntt` builds the Algorithm 42 candidate and proves its forward
relation. `verify_inverse_ntt` checks the wrapper version and invokes
`verify_ntt` with `(expected_output, expected_input)`. The inherited shape,
canonical range, proof-size, layout, options and endpoint checks all apply.
The example's native signature, streaming SHAKE and interpolation computations
are independent controls. They do not prove signature validity inside an AIR.

Intermediate states are public, and artifacts are not compact. The complete
matrix equation, norms/hints, challenge recomputation, canonical-source/private
witness links and actual node admission, persistence, import, replay, rollback
and activation remain unfinished. No consensus gas, fee, carrier or activation
rule changes here. Other parameter sets and platform combinations remain open.

## Design decision and regressions

Status: accepted for this standalone component. Use bijectivity and the existing
qualified forward relation instead of maintaining a duplicate inverse AIR.
This preserves its arithmetic constraints and proof format. It proves the
inverse result, rather than asserting an additional execution trace for Algorithm 42.

```bash
cargo test -p shell-stark-prover mldsa_inverse -- --nocapture --test-threads=1
```

Checks compare Algorithm 42 with independent interpolation for mixed, zero,
maximum and basis inputs; establish the fixed roots and normalization; verify
a real certificate and JSON round trip; reject changed stages/endpoints,
versions, layouts, malformed payloads and noncanonical data. A genuine valid
forward proof for an unscaled candidate rejects the original inverse statement
while verifying the appropriately scaled statement. Existing forward-AIR range,
carry and invalid-Boolean regressions remain applicable without duplicating them.
