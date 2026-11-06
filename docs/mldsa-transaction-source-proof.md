# Same-identity transaction source and signature proof

The public development verifier checks the complete ML-DSA-65 signature and both
source hashes in one graph. It proves the existing canonical outer transaction
signing payload's BLAKE3 digest, the full raw public-key BLAKE3 digest and the
ML-DSA-65 signature over that exact 32-byte signing digest. A mathematical proof
for a different key or message cannot be substituted.

This composes the [BLAKE3 source hash proofs](blake3-source-proof.md) and
[complete public ML-DSA-65 signature proofs](mldsa-verification-proof.md).
The supported signature interface is pure ML-DSA-65 with an empty context.
Only outer transaction types 0 through 3 are accepted by this combined entry.
Native AA sender signatures use separate bundle framing and are explicitly
rejected, along with other unsupported transaction types.

All states and source operands are public. This establishes source hashing and
signature mathematics for caller-supplied expected inputs. The caller must
authenticate the expected transaction, full key hash, raw key and raw signature
from its application or canonical source. Account authority, chain history,
private/compact/recursive proofs, other algorithms and actual node settlement,
import/replay/rollback, fees and network activation remain unfinished. This is
an unreleased source entry, not a released node command or a compact network
proof carrier.

## One regression entry

Use the source revision containing this guide, the repository's stable Rust
toolchain and locked dependencies. From the repository root:

```bash
mkdir -p proof-dir
tests/e2e/mldsa-source-proof.sh prove proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection
```

No node, funds, preexisting account or saved secret key is needed. The source
producer generates a temporary ML-DSA-65 account and a transaction, signs the
actual current signing hash, and writes only its public identity and source
record. Its secret key is never serialized or printed. The hash and complete
signature graphs use that same saved identity throughout.

The command runs these dependent stages in order and records each exit status:

1. Generate or reuse the transaction and full raw-key BLAKE3 hash proofs.
2. Generate or resume all 30 matrix-coordinate certificates for this key's rho.
3. Generate or reuse raw decoding, challenge, forward transforms, full equation
   and inverse-transform certificates.
4. Generate or reuse norm/hint/packing and tr/mu/final SHAKE certificates.
5. Honestly prove a canonical altered-hint signature's computations.
6. Verify the complete positive source/signature graph in a separate process.
7. Reject changed sources, unsupported types and the honestly proved invalid
   same-message signature through the combined production entry.

Full generation can take more than an hour. Every stage reuses completed valid
checkpoints and refuses to overwrite an existing file. Matrix coordinates are
saved separately, allowing incremental progress. Failures return a nonzero exit
and retain files and diagnostics. The public-key hash, source identity and first
matrix certificate must remain unchanged when generation resumes. Partial-file
recovery after interrupted writes remains unqualified.

To verify an existing complete checkpoint without generating any proofs:

```bash
tests/e2e/mldsa-source-proof.sh verify proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection
```

The constituent entries remain available for bounded matrix work:

```bash
cargo run --locked -p shell-stark-prover --example blake3-sources -- prove proof-dir/source
cargo run --locked -p shell-stark-prover --example mldsa-matrix -- prove proof-dir/source 1
```

The one-coordinate invocation reports `full_matrix_verified: false`. Resume
through the main regression command; it verifies the existing coordinate and
generates the remaining 29. A matrix or signature certificate from an earlier
identity with a different rho is not reusable for this identity.

## Production composition

`TransactionSignatureProof` version 1 contains two `Blake3HashProof` values and
one `Mldsa65VerificationProof`. It is serializable; the source example loads the
existing component files rather than duplicating large certificates in another
artifact. The production library function is `verify_transaction_signature`.

Its caller supplies the expected outer `Transaction`, raw public key, raw
signature and full public-key hash. There is no caller-supplied signing digest.
The function:

1. Rejects unsupported versions, key/signature shapes and AA/unsupported types.
2. Verifies the canonical outer payload's actual BLAKE3 proof under the fixed
   ML-DSA-65 signing algorithm byte.
3. Verifies the full raw key's actual BLAKE3 proof against the expected key hash.
4. Verifies the complete signature against the expected raw key/signature and
   the signing digest authenticated by step 2.

Every matrix coordinate, hash permutation, transform, equation coordinate, norm,
hint and final challenge comparison remains checked by the underlying component
verifiers. Native hash and signature implementations are independent producer
controls, not fallback acceptance paths in this combined verifier.

The existing batch-entry identifier mapping is preserved: Embedded entries use
the raw key's first 32 bytes and Reference entries use the sender address. The
full-key hash proof does not change those mappings, authenticate an account or
prove address derivation. Transaction encoding and consensus activation are
unchanged.

## Adversarial acceptance

The combined regression changes nonce, chain ID, data, the final raw-key byte,
raw signature and expected full-key digest. It also changes the proof version
and signing digest, and rejects AA and unknown transaction types. Changing the
last raw-key byte preserves rho but must still fail the full-key source binding.

For the substantive invalid-signature case, it removes one hint while retaining
canonical sparse encoding and the same c-tilde, z, key and signed message. New
real decoder, hint/packing and final SHAKE certificates honestly prove that
altered computation. Both source hashes and the unchanged equation prefix remain
valid. The complete combined verifier must reject specifically at
`signature: final commitment`, not merely because an unrelated source changed.

The qualified positive scenario is an ordinary type-0 transaction and a generated
ML-DSA-65 identity. Other transaction/algorithm/profile combinations, account
state changes and native network processing require their own acceptance.

## Design decision

Status: accepted for public source/signature composition.

Reuse the qualified component formats and backend. Compose against explicit
caller expectations and derive the signature message only from a verified
source hash. Reuse persisted checkpoints for the same identity. Do not change
legacy identifiers, native AA framing, activation, gas or protocol carriers to
make the development graph fit.
