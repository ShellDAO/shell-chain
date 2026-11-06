# ML-DSA-65 challenge sampling proof

This development source component proves `SampleInBall` for ML-DSA-65: a 48-byte
commitment seed is expanded with SHAKE256, rejection-sampled in order, and mapped
to a 256-coefficient polynomial with exactly 49 nonzero coefficients in
`{-1, 0, 1}`. It links the sampler AIR to the
[SHAKE sponge proofs](shake-sponge-proof.md), including every full Keccak
permutation. All intermediate values are public.

The specification is [FIPS 204, Algorithm 29 and Table 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
August 13, 2024. The native reference uses ML-DSA-65 with `tau = 49` and a
48-byte commitment seed. Other parameter sets are outside this API. This is a
source component of the full signature verification target; matrix sampling,
the signature equation, private witness binding and node settlement remain
unfinished. It is not a NIST-validated module or a released node command.

## Run the source example

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), the
repository's stable Rust toolchain and locked dependencies. From the repository
root, run:

```bash
cargo run -p shell-stark-prover --example mldsa-challenge -- prove challenge.json
cargo run -p shell-stark-prover --example mldsa-challenge -- verify challenge.json
```

No node, account, funds or saved keys are needed. The example generates a
temporary ML-DSA-65 key in memory, signs a public example message, and binds the
challenge seed to the first 48 bytes of the genuine signature. Only the public
key, message, signature and proof are written. The private key is not printed or
stored. The artifact path must be new; existing paths are not overwritten.

`prove` verifies the result against an independent streaming SHAKE256 sampling
oracle, syncs the JSON and verifies the reloaded file. The separate `verify`
invocation loads existing proof data without generating another proof. It checks
the native signature as a control, checks the expected challenge from the
independent oracle, and verifies both the sampler and the complete SHAKE proof
chain. Errors return a nonzero exit code. Native signature validity remains
separate from the AIR; this example does not prove the complete signature.

## Sampling and state constraints

The first eight XOF bytes provide sign bits. Sampling starts at polynomial index
207. Every following byte is consumed in order: values above the current index
are rejected without advancing it; an accepted byte selects an index, moves its
old coefficient to the current position, and writes the selected sign at the
selected index. When the indices coincide, the sign write has final priority.
All 256 coefficients are checked for every one of the 49 accepted updates.

The trace has 27 columns and 22 constraints, with maximum degree four. Each
attempt constrains a Boolean acceptance flag, an eight-bit comparison difference,
a six-bit counter slack, the accepted-index link and the counter increment.
These bounds establish both directions of the acceptance comparison, including
equality. The public counter sequence starts at zero and ends at 49; an
additional attempted byte after reaching 49 is invalid. Fixed raw-byte routing
prevents skipping rejected bytes.

For each accepted update, public routing binds the old and new full polynomial,
the old selected coefficient, sign bit and both position selectors. The AIR
constrains the assignment order, every unchanged coefficient, and the ternary
domain of all old/new coefficients. The initial polynomial is fixed to zero.
The final Hamming weight follows from these 49 updates and accepted index bounds;
it is not established by a native verifier-side sampling or weight filter.

Twelve fixed even-row sequence assertions bind public operation values; fifteen
private Boolean columns enforce the acceptance flag and comparison/slack bits.
The verifier does fixed public routing and actual STARK verification, then checks
the SHAKE sponge/permutation proofs. It does not run native SHAKE, SampleInBall
or its acceptance comparison as a substitute for the AIR. Only the final unused
odd row carries statement-derived trace padding.

`ChallengeProof` version is 1, with statement domain `MLCHAL01`.
`verify_challenge` requires the expected 48-byte seed and 256-coefficient output
from the caller. Malformed shapes, endpoints, versions, proof layouts and
payloads are rejected. The sampler proof payload is limited to 1 MiB. Readers
must also bound untrusted JSON before parsing. SHAKE public state lanes use
unsigned 64-bit values; the Rust reader preserves them exactly.

The prover starts with a 128-byte XOF output. If more bytes are needed, it doubles
that output up to the existing 4096-byte development limit, then returns a
resource error if sampling still cannot finish. The trace is normally 32768
rows and can reach 65536 rows at that bound. These bounds do not set consensus
gas, fees or network validation rules. Exceptional real seeds requiring prefix
extension and the maximum-size trace are not claimed by the listed tests.
All states, indices, counters and XOF bytes are public, so the artifact is neither
private nor compact.

## Design decision

Status: accepted for this development component.

Reuse the existing Winterfell field, proof options and complete SHAKE proof
chain. Keep the consumed-byte counter and polynomial states public, bind their
routing with fixed assertions, and put comparison bounds and update arithmetic
inside the AIR. This gives an independently verifiable sampling relation with
no new backend or proof carrier. The public state increases artifact size and
verifier inputs. Private state commitments, compact aggregation and protocol
resource limits remain separate integration work.

## Regression entry

```bash
cargo test -p shell-stark-prover mldsa_challenge -- --nocapture --test-threads=1
```

Real proofs cover zero, all-`ff` and genuine signature seeds, independent native
sampling outputs and JSON reload. Synthetic rows separately cover repeated
rejections, repeated selected indices, coincident indices, assignment order and
all unchanged coefficients; they are not claimed as real SHAKE samples. A
constructed forged acceptance satisfies the linear equalities but fails the
Boolean range constraints. Further checks reject altered counters, indices,
intermediate/invalid ternary states, sign-stream bytes, malformed endpoints and
proofs, and corrupted inner SHAKE/Keccak proofs. Full signature equations,
canonical-source authentication, private witnesses and actual node import,
replay, rollback and activation acceptance remain open.
