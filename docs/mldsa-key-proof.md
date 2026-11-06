# ML-DSA public-key decoding proof

This development-source component proves ML-DSA-65 public-key decoding from
[FIPS 204, Algorithms 18 and 23](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
It binds all 1952 public key bytes to 32 rho bytes and six t1 polynomials,
each containing 256 ten-bit coefficients. Public-key encoding interpretation
does not establish possession of a private key or signature validity.

With the repository's stable Rust toolchain, from a development source checkout:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-key -- prove key-proof.json
cargo run --locked -p shell-stark-prover --example mldsa-key -- verify key-proof.json
cargo test --locked -p shell-stark-prover mldsa_key::tests::
```

The example generates a temporary in-memory ML-DSA key and a genuine signature,
checks that signature natively, and produces an actual public-key decoding
STARK. It shifts the **first** decoded t1 polynomial by 13 bits, as used in the
verification equation, and proves its [forward NTT](mldsa-ntt-proof.md).
The maximum scaled coefficient is `1023 * 8192 = 8380416`, below the modulus.
An independent direct polynomial evaluation checks the expected NTT output.

The caller-owned JSON file is created only if it does not exist, synchronized,
and reloaded. The separate `verify` command runs in a new process without
generating another proof. Changed decoded t1 and a changed native message are
rejected. Errors exit nonzero. Private keys are never printed or persisted;
the artifact contains only public keys, messages, signatures and proofs.

The AIR uses 40 boolean witness bits per five encoded bytes, with equations
for all five bytes and all four decoded ten-bit coefficients. Copy rows bind
rho. Fixed even-row assertions cover every real operation; the final unused
odd row contains statement-derived padding for constant encodings. The
verifier checks shape and the AIR without rerunning the native key decoder.
In particular, a decoded coefficient of 1024 is rejected by the AIR rather
than a native ten-bit range filter.

All raw and decoded data is public. No zero-knowledge, compression, performance
or complete PQ signature-verification claim is made. The [signature encoding
component](mldsa-decoding-proof.md) is separate. SHAKE, challenge sampling,
inverse NTT/matrix relations, norms, hint application, canonical source binding
and full node admission/settlement integration remain unfinished. Neither
artifact is a node `SigBatchProof`, and these examples require the development
source tree rather than a currently released node binary.
