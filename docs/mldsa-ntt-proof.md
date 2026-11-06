# Forward ML-DSA NTT arithmetic proof

This development-source component implements a Winterfell AIR for the complete
256-coefficient forward NTT in [FIPS 204, Algorithm 41](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
It is one arithmetic component toward the full signature-verification circuit.
Signature decoding, SHAKE, norm/hint checks and binding to signatures remain
unimplemented in this component. It is not a signature batch or settlement proof.

From a development source checkout, with the repository's stable Rust toolchain:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-ntt -- prove ntt-proof.json
cargo run --locked -p shell-stark-prover --example mldsa-ntt -- verify ntt-proof.json
cargo test --locked -p shell-stark-prover mldsa_ntt::tests::
```

The example uses an explicit public test polynomial, checks the result using
independent direct polynomial evaluation, generates an actual STARK, and writes
a new JSON artifact. It reloads that file and verifies against independently
supplied input/output, then rejects altered intermediate coefficients, output
and truncated proof bytes. The separate `verify` command repeats verification
in a new process without generating another proof. No accounts or keys are required. The output file
must not already exist. Errors and failed assertions exit nonzero. The example
is not included in the currently published node binary.

The proof covers all eight stages and 1024 butterflies with modulus 8380417
and the specified powers of 1753. All nine polynomial states are public.
Sequence boundary assertions bind each butterfly's inputs, outputs and twiddle
to those states, including the final butterfly. The AIR checks multiplication
with quotient/remainder reduction, addition/subtraction, and boolean carries.
Both private quotient and remainder are constrained by 23-bit decompositions
of the value and its complement to `q-1`, proving canonical values below `q`.
All integer products are below `q²`, far below the f128 field modulus, so field
wraparound cannot satisfy an invalid integer equation.

The final odd trace row carries no operation or boundary assertion. It is
filled from a domain-separated hash of the public statement to avoid
degenerate constant trace polynomials. The last real butterfly is on the
preceding even row and remains covered by every arithmetic and range check.

Public intermediate states are an explicit cost of this representation. No
zero-knowledge, signature-compression, throughput or complete PQ verification
claim is made. The verifier checks the AIR and expected endpoints without
recomputing the NTT. The artifact has its own version and fixed trace layout;
it is not accepted by the node's existing `SigBatchProof` admission path.
