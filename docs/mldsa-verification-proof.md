# Complete public ML-DSA-65 signature proof

The development verifier checks a complete ML-DSA-65 signature predicate using
linked STARK certificates: raw key/signature decoding, matrix expansion,
challenge sampling, all forward transforms, the full six-row equation, all
inverse transforms, strict z norms, hint recovery, w1 encoding and all three
SHAKE256 hashes. It checks the final 48-byte result against the challenge in the
original signature. The production verification path does not call a native
signature verifier or recompute these cryptographic operations natively.

The specification is [FIPS 204, Algorithms 3, 8, 28, 36 and 40](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
August 13, 2024. Supported inputs are ML-DSA-65 pure signatures with an empty
context and messages of at most 4030 bytes. The message bound comes from the
4096-byte SHAKE development input limit after adding 64-byte tr and the two
context-framing bytes. Other parameter sets, nonempty contexts and prehashed
signatures are unsupported.

All component states and operands are public. This is a large development
certificate; it does not establish private witnesses, canonical transaction
provenance, recursive aggregation, node settlement, network activation or a
released node CLI. It is not a NIST-validated module. The full PQ aggregation
feature still requires those integration and delivery steps.

## Reproduce from source

Use a checkout of [shell-chain](https://github.com/ShellDAO/shell-chain), the
repository's stable Rust toolchain and locked dependencies. From its root:

```bash
cargo run -p shell-stark-prover --example mldsa-matrix -- prove matrix-dir
cargo run -p shell-stark-prover --example mldsa-equation -- prove matrix-dir equation-dir
cargo run -p shell-stark-prover --example mldsa-verify -- prove matrix-dir equation-dir signature-dir
cargo run -p shell-stark-prover --example mldsa-verify -- verify matrix-dir equation-dir signature-dir
cargo run -p shell-stark-prover --example mldsa-verify -- check-rejections matrix-dir equation-dir signature-dir
cargo run -p shell-stark-prover --example mldsa-verify -- reject-hint-tamper matrix-dir equation-dir signature-dir rejection-dir
```

No node, funds or preexisting account/key is required. The matrix example creates
a temporary key in memory, signs its own public message and saves only the public
identity. Matrix generation can take tens of minutes; completed coordinate
checkpoints can be reused as described in [the matrix guide](mldsa-matrix-proof.md).
The [equation guide](mldsa-equation-proof.md) describes its 22 saved component
proofs. The final example reads both directories without writing to them and
adds `identity.json`, `finish.json`, `tr.json`, `mu.json` and `commitment.json` to
a separate signature directory. Existing files are reloaded and checked, never
overwritten. Keep completed checkpoints to avoid regenerating equivalent proofs.

The final `verify` invocation uses the library verifier in a separate process,
creates no proofs and checks the complete graph against the saved raw public key,
message and signature. The native signature verification in the example is an
independent control evaluated after the STARK verification path. Applications
using the library must provide their own authenticated expected statement;
accepting an arbitrary saved identity does not authenticate a transaction source.

`check-rejections` checks the valid prefix/completion once, then rejects changed
expected key/signature/message, authenticated hints/z, final hint output, packed
byte, tr/mu hash and final hash proof, plus an oversized message. It creates no
proofs and reports each rejection phase.

Ordinary proving/verifying errors return a nonzero exit code. The final negative
regression command succeeds only when it observes the expected rejection. It
changes one hint while maintaining canonical sorted sparse encoding, proves the
new encoding, verifies the unchanged full equation prefix, and proves the new
hint result and its honest SHAKE hash. That hash certificate verifies against
its own output but must fail against the original challenge. Rejection must occur
at `final commitment`, and an independent native verifier must reject too. New
negative checkpoints are kept in the rejection directory; positive input files
remain intact. Recovery after a partial interrupted file write is unqualified.

## Finish constraints

The finish AIR has 75 columns, 80 constraints with maximum degree three, 8192
trace rows and six fixed public sequence assertions on even rows. It covers
1536 hint operations, 1280 norm operations and 768 nibble-packing operations.
The 3584 operations occupy the start of 4096 slots; zero selectors disable the
remaining dummy operations. Only the final unused odd row carries padding.

For q = 8380417, gamma2 = 261888 and alpha = 2 gamma2, the decomposition is

```text
r = alpha * high + low + q * wrap
-gamma2 <= low <= gamma2
0 <= high <= 15
```

Nineteen-bit low/complement decompositions establish the interval. A Boolean
wrap flag forces high to zero in the exceptional q-1 range. A private inverse
of `low + gamma2 + wrap` excludes the negative tie when wrap is zero, preserving
the right-closed normal interval while allowing the wrapped negative tie.
Canonical public r plus these bounds force the unique FIPS decomposition.

An 18-bit gap proves whether low is strictly positive. In particular low = 0
takes the decrement branch when the hint is one. Boolean carry flags and four-bit
high/result decompositions prove adjustment modulo 16, including both wraps.
Hints are Boolean in AIR; their total weight and canonical sparse encoding are
already proved by the raw signature decoder.

For each canonical z coefficient, a Boolean sign relates it to a 19-bit absolute
value. A second 19-bit complement proves magnitude at most 524091, enforcing the
strict bound `||z|| < gamma1 - beta = 524092` for both signs. Packing constraints
bind `byte = first_nibble + 16 * second_nibble`; every nibble is bound to a
proved hint result. No native hint/norm/packing filter replaces these constraints
in the verifier. All 68 private bit columns have Boolean constraints. Bounded
integers exclude aliases in the much larger proof field.

`FinishProof` version 1 uses statement domain `MLFIN001`. Input dimensions and
canonical field residues are checked before trace handling. The verifier checks
the exact trace layout, bounded proof payload and the standard proof options.
It independently binds expected input and output arrays.

## Complete graph and hash binding

`verify_equation_pipeline` authenticates the raw key and signature with actual
decoder proofs. It verifies all 30 matrix coordinates under decoded rho and
samples the challenge under decoded c-tilde through the SHAKE and sampler
proofs. It binds all five z transforms, six transforms of scaled t1, the
challenge transform, the full equation and six inverse certificates. Claimed
outputs are usable only after their mathematical component proofs verify.

The returned `VerifiedEquation` token has private fields, no public constructor
and no deserialization. A producer can check the expensive prefix once and use
`verify_completion` after generating the remaining proofs. `verify_mldsa65`
checks the entire version-1 `Mldsa65VerificationProof` for external callers.

Completion verifies the finish AIR and these actual SHAKE256 proof chains:

```text
tr     = SHAKE256(raw_public_key, 64)
mu     = SHAKE256(tr || 00 || 00 || raw_message, 64)
c_next = SHAKE256(mu || encoded_w1, 48)
c_next == decoded_original_c_tilde
```

All Keccak permutations, sponge state bridges and padding are checked through
the existing [SHAKE proof implementation](shake-sponge-proof.md). The last
equality is against the caller-bound original signature, not merely the final
certificate's claimed hash. A proof of a correct computation for an invalid
signature cannot satisfy that equality.

These are separate certificates linked by public operands, with no recursive
backend or compact network carrier. Applications must bound untrusted JSON
before parsing and budget the full verification work. The development bounds
do not define consensus gas, fees or activation rules.

## Design decision and regression entry

Status: accepted for the bounded public source verifier.

Reuse the existing backend and each qualified component format. Add only the
missing finish constraints and an explicit production composition function.
Keep native calculations in the prover or independent example controls. Reuse
completed matrix/equation files and retain failed artifacts for diagnosis.
Private/canonical/node integration remains separate work under the existing
protocol decisions.

```bash
cargo test -p shell-stark-prover mldsa_finish::tests -- --nocapture
```

Tests cover real mixed-boundary/zero proofs, saved JSON, ties and q-1 wrap,
strict signed norm boundaries, last coordinates and nibble order. Adversarial
private witnesses satisfy the arithmetic equalities while violating Boolean
range constraints for positivity, norm complements and high/result overflow.
The negative normal tie violates the dedicated nonzero constraint. Mutated
endpoints, malformed shapes, foreign layouts and invalid payloads are rejected.
Use the complete example above for genuine signature and honest-computation
altered-hint acceptance/rejection; individual AIR tests do not establish that
full graph on their own.
