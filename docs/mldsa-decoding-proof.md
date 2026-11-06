# ML-DSA signature decoding proof

This development-source component proves the ML-DSA-65 encoding interpretation
specified by [FIPS 204, Algorithms 19, 21 and 27](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
It binds the 3309 public signature bytes to 48 challenge bytes, five decoded
z polynomials and six hint maps. z coefficients use canonical representatives
modulo 8380417, suitable as inputs to the [forward NTT component](mldsa-ntt-proof.md).

With the repository's stable Rust toolchain, from a development source checkout:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-decode -- prove signature-proof.json
cargo run --locked -p shell-stark-prover --example mldsa-decode -- verify signature-proof.json
cargo test --locked -p shell-stark-prover mldsa_decode::tests::
```

The example generates a temporary ML-DSA key in memory, signs a message and
checks the signature natively. It generates an actual decoding STARK and a
forward NTT proof for the **first** decoded z polynomial, independently checks
the NTT output by polynomial evaluation, and persists a new JSON artifact.
The separate `verify` command reloads the artifact in a new process and checks
the native signature and both proofs. It also rejects changed decoded z and
a changed native message. The existing output file is never overwritten;
failed verification exits nonzero. Only public keys, messages, signatures and
proofs are stored; the private key is never printed or saved.

The AIR constrains 20-bit coefficient unpacking and signed-to-canonical-field
conversion. Hint constraints enforce nondecreasing delimiters bounded by 55,
strictly increasing positions within each polynomial, selected output entries
equal to one, and zero unused encoded bytes. Public hint output entries are
nonnegative bytes. Their sum must equal the encoded count, so the distinct
selected entries account for every nonzero output. Challenge-byte copy rows
bind the remaining signature prefix. Public indices route boundary assertions;
the verifier does not run the native signature decoder to decide validity.

All raw bytes and decoded outputs are public. This representation makes no
zero-knowledge, signature-compression or throughput claim. Native signature
verification is separate: the decoding AIR does not check SHAKE, message/key
binding, norms, hint application or the full signature verification equation.
Only the first z polynomial is passed to the NTT in this example. The full PQ
signature AIR and node admission/settlement integration remain unfinished.
Neither artifact is a node `SigBatchProof`, and these examples require the
development source tree rather than a currently released node binary.
