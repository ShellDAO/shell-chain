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
prove address derivation by itself. The optional derived-sender predicate below
adds address derivation without changing those mappings. Transaction encoding and consensus activation are
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

## Address-derived Embedded sender

To also prove the sender address, supply one additional output directory:

```bash
tests/e2e/mldsa-source-proof.sh prove proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection proof-dir/sender
```

This resumes the same public source/signature graph and produces one new
BLAKE3 hash certificate for `ML-DSA-65 algorithm byte || raw public key`.
The preimage is 1,953 bytes; it differs from the 1,952-byte raw-key hash and
requires its own compression certificates. No new secret key or signature is
needed. `sender.json` records the public expected `SignedTransaction` with its
full 32-byte `from`, Embedded key and signature. `sender-address.json` records
the actual address hash proof. Existing valid files are reused; existing files
are never overwritten.

To independently reopen the complete graph without generating any proofs:

```bash
tests/e2e/mldsa-source-proof.sh verify proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection proof-dir/sender
```

For a previously complete source/signature checkpoint, run just the new stages:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-source -- prove-derived proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender
cargo run --locked -p shell-stark-prover --example mldsa-source -- verify-derived proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender
cargo run --locked -p shell-stark-prover --example mldsa-source -- check-derived-rejections proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender
```

The production `verify_derived_sender_signature` takes a
`DerivedSenderSignatureProof`, a caller-expected `SignedTransaction` and the
expected full raw-key hash. It requires ML-DSA-65, an Embedded key and ordinary
outer framing. It verifies the prefix/key hash against the expected `from`,
then the transaction source, raw-key hash and complete signature against that
same envelope. The address comes from the caller expectation; accepting a
certificate's self-declared address alone would not bind the sender. Native
address hashing is only an independent producer control.

This predicate covers address-derived senders such as initial Embedded
registration. It does not prove that a registry entry is absent, that the
account can register a key, or that the account has sufficient funds or the
correct nonce. Native validation derives the address when no key is registered.
Registered accounts instead resolve the canonical key and enforce stored
key-hash and activation rules, including legacy raw-key hashes and activated
algorithm-bound hashes. A rotated key may retain the original account address;
this predicate must not replace those stateful rules or impose address
rederivation on every Embedded transaction. Reference authorization, registry
history, canonical state and native AA/session framing remain unfinished.

The regression rejects changed expected `from`, the last Embedded-key byte,
algorithm, nonce, signature, raw-key hash and malformed signature size. It also
rejects Reference and AA inputs, wrong proof versions, algorithm prefix/digest
changes, missing/extra compressions and changed compression arithmetic. An
honest valid raw-key hash certificate is independently verified and then
substituted for the address certificate with `from` set to its output; the
combined predicate still rejects the missing algorithm domain. These checks
exercise the complete persisted positive graph before adversarial cases.

Design decision: retain the native algorithm-prefixed address format and
existing signature-source composition. Keep the stateless address-derived
predicate explicit so that registered/rotated authorization is not silently
narrowed. No consensus IDs, activation heights, gas or proof carriers change.

## Canonical transaction ID

An ordinary canonical transaction ID is
`BLAKE3(PQTX_ID_DOMAIN || from32 || sender_signing_hash32)`, where the identity
domain is the existing 16-byte `PQTX_IDENTITY_V1`. This differs from the
transaction's signing digest. To prove this ID as well, add an ID directory:

```bash
tests/e2e/mldsa-source-proof.sh prove proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection proof-dir/sender proof-dir/id
```

The ID stage reuses the same source, full signature and derived-sender graph.
It saves an independently expected ID in `id-source.json` and a real BLAKE3
hash proof in `id-hash.json`. The new preimage is 80 bytes and needs two new
compression certificates. Existing files are never overwritten. The native
ID computed from a freshly loaded envelope is an independent producer control.

To reopen the complete persisted graph without generating proofs:

```bash
tests/e2e/mldsa-source-proof.sh verify proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection proof-dir/sender proof-dir/id
```

For an existing complete derived-sender checkpoint, run only the new stages:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-source -- prove-identified proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender proof-dir/id
cargo run --locked -p shell-stark-prover --example mldsa-source -- verify-identified proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender proof-dir/id
cargo run --locked -p shell-stark-prover --example mldsa-source -- check-identified-rejections proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender proof-dir/id proof-dir/rejection
```

The production `verify_identified_sender_signature` takes an
`IdentifiedSenderSignatureProof`, caller-expected `SignedTransaction`, full
raw-key hash and independently expected canonical ID. It verifies the identity
hash against the exact native domain, full `from` and signing digest carried by
the source graph, then authenticates that digest through the complete derived
sender/source/signature predicate. All checks must succeed. It does not accept
`SignedTransaction::hash()` or the certificate's self-declared output as a
substitute for either check.

Authentication witnesses remain excluded from the ID. The regression verifies
that changing Embedded to Reference preserves the native ID, while the proof
predicate still rejects Reference because canonical registry authority is not
proved. Likewise, the honestly proved invalid altered-hint signature retains
the same valid canonical ID but must fail at `signature: final commitment`.
A valid identity hash alone is insufficient authentication.

Other checks change the expected ID, the upper address byte while retaining
the last 20 bytes, the signing digest, domain, proof versions, output,
compression coverage and compression arithmetic. A valid signing-hash
certificate cannot replace the canonical-ID certificate. The regression also
populates the native hash cache before changing the transaction nonce: even
though the native cached value remains unchanged, the proof predicate must
reject the changed canonical source.

This proves a canonical ID's derivation, not membership in a canonical chain,
source ordering, a transaction receipt or settlement. Registry/account state,
registered/rotated authorization, Reference, AA/session framing, history,
import/replay/rollback, fees/resources, private proofs and node integration
remain outside this bounded public predicate. The qualified positive envelope
is still the generated ordinary type-0 ML-DSA-65 transaction.

Design decision: expose the existing native identity-domain constant and reuse
its unchanged 16+32+32-byte layout. Link the ID proof to the same full sender
and source/signature graph; keep witness exclusion distinct from authentication.
No native hashing behavior, identifier format, cache semantics, consensus
carrier or activation policy changes.

## Authenticated batch entry and leaf

The existing batch entry uses the **sender signing digest**, rather than the
canonical transaction ID, as `msg_hash`. For Embedded keys its legacy
`pk_hash` field contains the first 32 raw key bytes (rho for ML-DSA-65). It is
neither the full raw-key digest nor the sender address. Reference entries use
the full sender address instead; authenticating that mode still requires
canonical registry/account evidence.

The native mapping now lives in `SigBatchEntry::from_signed_transaction`.
Node source reconstruction delegates to this same mapper; production, import
and recovery retain the existing mapping and roots. The mapper itself does
not verify a signature. Its existing native regression covers full-width
Reference addresses, Embedded raw-key prefixes and short-key zero padding.

Add an entry directory to prove its actual BLAKE3 leaf as well:

```bash
tests/e2e/mldsa-source-proof.sh prove proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection proof-dir/sender proof-dir/id proof-dir/entry
```

This reuses the complete same-identity graph. `entry-source.json` saves the
independently native-derived expected entry and leaf; `entry-leaf.json` saves
the actual BLAKE3 proof. The new preimage is `msg_hash32 || pk_hash32`, exactly
64 bytes, and needs one compression certificate. Existing files remain
unchanged and no saved private key is needed.

To independently reopen the full persisted graph without generating proofs:

```bash
tests/e2e/mldsa-source-proof.sh verify proof-dir/source proof-dir/equation proof-dir/signature proof-dir/rejection proof-dir/sender proof-dir/id proof-dir/entry
```

For an existing complete identified-sender checkpoint, run just the new stages:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-source -- prove-entry proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender proof-dir/id proof-dir/entry
cargo run --locked -p shell-stark-prover --example mldsa-source -- verify-entry proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender proof-dir/id proof-dir/entry
cargo run --locked -p shell-stark-prover --example mldsa-source -- check-entry-rejections proof-dir/source proof-dir/equation proof-dir/signature proof-dir/sender proof-dir/id proof-dir/entry proof-dir/rejection
```

`verify_signature_entry` takes a `SignatureEntryProof`, expected signed
transaction, full raw-key hash, canonical ID, native entry and leaf. It checks
the exact Embedded entry mapping, the real leaf hash proof and the complete
identified sender/source/signature graph. Native mapper and hash calls are
producer controls; the verification predicate has no native cryptography
fallback. Only success returns a `VerifiedSignatureEntry` snapshot with
immutable getters for entry, leaf and transaction ID. The snapshot has no
public constructor or deserializer; consumers must verify persisted proofs
rather than trusting a serialized claim that an entry was verified.

The regression changes proof versions, leaf message/output, compression
coverage/arithmetic and the expected leaf. It rejects canonical-ID-as-message,
full-key-hash/address-as-Embedded-identifier, Reference inputs and an honest
valid ID certificate substituted for the leaf certificate. Changing the last
raw-key byte preserves rho and therefore the native legacy entry and leaf;
the complete predicate must still reject the full-key source mismatch.
The honestly proved invalid altered-hint signature likewise retains its valid
native entry, leaf and canonical ID, but must fail at
`signature: final commitment`. A valid legacy leaf alone is insufficient
authentication of a full key, signature or sender.

This bounded public predicate covers the same ordinary type-0 ML-DSA-65
Embedded envelope. It does not establish source order, an ordered multi-entry
batch, canonical chain membership, registry absence/account authority,
registered/rotated or Reference authorization, native AA, fees/resources,
private proofs, settlement or node acceptance. Those remain separate work.

Design decision: share the unchanged native mapper and preserve its legacy
field meanings. Authenticate that entry with actual source/signature and
BLAKE3 proofs, and expose a verified snapshot only after every check succeeds.
No batch roots, transaction IDs, consensus carriers, gas or activation policy
changes.

## Actual authenticated ordered batch

`verify_authenticated_sig_batch` verifies the existing native `SigBatchAir`
accumulator over `VerifiedSignatureEntry` snapshots. It requires a nonempty
batch, the current native proof version, exact count, unique transaction IDs,
exact caller-expected ID order and independently expected root. It folds the
already-proved full leaf bytes using the same little-endian f128 conversion
and dual accumulator as the native batch. It then verifies the actual native
STARK proof. Native BLAKE3 and signature functions are not acceptance fallbacks.
The existing commitment-only/native entry APIs and on-chain proof layout remain
unchanged.

One regression entry builds two complete real signature graphs and the native
batch proof:

```bash
mkdir -p proof-dir
tests/e2e/mldsa-batch-proof.sh prove proof-dir/first proof-dir/second proof-dir/batch
```

This is sustained CPU work and may take several hours from an empty checkpoint.
The second identity is a newly generated ML-DSA-65 account with a distinct key,
rho, sender address, canonical ID and leaf. Its private key exists only while
signing in memory and is never saved or printed. Both accounts sign the same
canonical outer payload; their native canonical IDs still differ because the
full sender is included. The exact transaction-hash certificate is copied only
after verifying the identical payload and algorithm bytes. Key hashes,
matrices, transforms, equation, completion, address, ID and leaf certificates
are specific to the second identity and must be generated for it.

The script saves and verifies the first new matrix coordinate before resuming
all remaining coordinates. Each stage records its exit status. Completed valid
files are reused, and existing files are never overwritten. All public source
records, individual certificates, expected order/root and native proof/control
files persist across processes. Interrupted partial-file recovery remains
unqualified.

For complete existing checkpoints, independently verify without generating
proofs:

```bash
tests/e2e/mldsa-batch-proof.sh verify proof-dir/first proof-dir/second proof-dir/batch
```

A graph directory contains `source`, `equation`, `signature`, `sender`, `id`,
`entry` and `rejection` subdirectories produced by the source regression entry.
Alternatively, a version-1 JSON path manifest can point to existing graph
components without moving or regenerating them. Paths are relative to that
manifest's directory:

```json
{
  "version": 1,
  "source": "first/source",
  "equation": "first/equation",
  "signature": "first/signature",
  "sender": "first/sender",
  "id": "first/id",
  "entry": "first/entry",
  "rejection": "first/rejection"
}
```

Pass that JSON file as the first graph argument to reuse a complete existing
graph. The producer verifies it before initializing the new account. Direct
batch-only entries are also available:

```bash
cargo run --locked -p shell-stark-prover --example mldsa-batch -- prove proof-dir/first proof-dir/second proof-dir/batch
cargo run --locked -p shell-stark-prover --example mldsa-batch -- verify proof-dir/first proof-dir/second proof-dir/batch
cargo run --locked -p shell-stark-prover --example mldsa-batch -- check-rejections proof-dir/first proof-dir/second proof-dir/batch
```

`batch-source.json` holds independent expected IDs/root; `batch-proof.json`
holds the actual native accumulator proof. Four additional honest native
proofs cover reversed, duplicated, dropped and foreign-leaf inputs. Their
native accumulator calculations verify for their own statements. The combined
predicate must still reject them against the expected authenticated source
context. A reversed batch also succeeds against its separately reversed
expected context, demonstrating order binding without a fixed expected result.
Other refusals cover empty/count/version/ID/root changes, corrupted proof bytes
and a correct commitment with no STARK proof. An honestly proved invalid
signature can retain the same native leaf and batch root; full entry verification
must reject it at the final signature commitment before a verified snapshot
exists.

These checks cover two distinct ordinary type-0 pure ML-DSA-65 Embedded
identities in this public development path. The caller must supply the expected
canonical source context: this predicate does not prove chain membership,
canonical registry/account state, transaction execution, fees/resources,
Reference/rotated authorization, AA, persistence/import/replay settlement,
private/compact proofs or node activation. Those remain separate acceptance.

Design decision: reuse the unchanged native accumulator, field conversion and
proof format. Share the fold between native and authenticated callers, feeding
only already-proved leaves to the latter. Verify complete source/signature graphs
before issuing entry snapshots, and bind their exact ordered IDs/root as caller
expectations. No legacy roots, gas, protocol carriers or activation rules change.

## Native account state and the signed batch

`AccountStateProof` authenticates membership or absence of a native account
under an independently expected state root. The account key is legacy
Keccak-256 of the **full 32-byte sender address**. The witness contains real
Keccak AIR certificates for that key and every referenced hashed MPT node.
Verification checks the original native account RLP, compact nibble paths,
branch/extension/leaf routing and exact node coverage. Inline children are
consumed from their parent. The native empty trie has an explicitly proved
empty RLP root. Native hashing or the native trie verifier is not an acceptance
fallback.

Keccak-256 uses rate 136, suffix `0x01` and exactly 32 output bytes. It has a
separate proof transcript tag from SHAKE. Existing SHAKE128/256 tags, padding,
public inputs and saved certificates retain their original meaning. A valid
SHAKE256 certificate for the same bytes cannot substitute for Keccak-256.

`verify_account_bound_sig_batch` joins account witnesses to the exact full
senders in immutable `VerifiedSignatureEntry` snapshots, the actual native
batch proof and the expected ordered canonical IDs/root. Only success returns
immutable account snapshots. They authenticate the complete account record,
including nonce, balance, key hash and custom-validator field.

Run the persisted regression from the repository root:

```bash
mkdir -p proof-dir
tests/e2e/mldsa-account-state-proof.sh prove proof-dir/first proof-dir/second proof-dir/batch proof-dir/state
tests/e2e/mldsa-account-state-proof.sh verify proof-dir/first proof-dir/second proof-dir/batch proof-dir/state
```

This needs the repository's Rust and native RocksDB build prerequisites. It
requires no RPC server, funds, personal paths or saved private keys. A missing
batch is built using the preceding two-identity regression; generating both
signature graphs from an empty directory can take several hours. Existing valid
source/hash/matrix/signature/batch certificates are reused. A version-1 first
graph path manifest is accepted as in the preceding section.

The new native fixture creates its own RocksDB database in `state/native-db`.
It commits actual account roots and native MPT proof nodes, then changes the
first account's nonce, balance and custom-validator field. Separate processes
reopen the old and current roots. Historical reads must preserve every native
state KV entry and the current account. Keep this database with the proof
checkpoints when resuming; partial fixture recovery is unqualified and existing
records are never overwritten.

`state-source.json` records the independently native-derived roots, full
addresses, accounts and raw proof nodes. Five account witnesses cover two real
signed senders, absence at a branch, absence at a mismatched leaf, and the empty
root. Content-addressed `hash-*.json` certificates are shared across paths.
`boundary-*.json` covers lengths 0, 3, 135, 136 and 137; independent native
implementations check the Keccak outputs. An honest SHAKE certificate and an
honestly hashed malformed RLP node are retained as rejection controls. The
verify command generates no proofs. Each stage exits nonzero on failure.

This establishes account state under the supplied root, plus its binding to
the two complete public signature graphs and native batch. The root's canonical
chain membership remains an independent requirement. The native public-key
registry is stored in a separate KV table and is **not** committed by the
account trie root. Account membership or absence therefore does not establish
registry absence, Reference/rotated-key authorization, account authority or
custom-validator execution. Those links, canonical replay/import/rollback,
private/recursive proofs and node activation remain separate work. No native
state commitment, root format, consensus carrier, gas or activation rule changes.


## Registered account key proofs and native execution

`verify_registered_signature_entry` combines an already verified account
snapshot with the complete ordinary ML-DSA-65 source/signature, canonical
transaction ID and native Embedded or Reference leaf. It proves the account's
legacy raw key hash, or its algorithm-tagged `algorithm byte || raw key` hash.
A retained sender address need not be derived from the current key. The bounded
profile rejects absent accounts, zero key hashes and custom validators.

`VerifiedRegisteredSignature` implements the existing crypto `Verifier` trait.
It returns true only for the exact proved key, signing digest, algorithm and
signature bytes. It never invokes a native signature verifier as a fallback.
`matches_transaction` also compares the sender, unsigned fields, witness mode
and signature without trusting the transaction's cached ID. The returned entry
can feed the existing authenticated native batch verifier.

This value is a cryptographic result, **not an authorization ticket**. Before
using it, callers must bind its account root and transaction to their independently
trusted parent state. Native transaction policy must still read the actual
registry and chain configuration and enforce key conflicts, tagged-key activation,
algorithm lifecycle, nonce, funds, fees and resource rules. Neither account MPT
proofs nor this crypto adapter commit the separate registry KV index or prove
canonical chain membership. A tagged-key proof remains mathematically valid
before activation; native policy must reject its unauthorized use then.

Run the complete local regression after the preceding account-state producer:

```bash
tests/e2e/mldsa-registered-proof.sh prove proof-dir/first proof-dir/second proof-dir/state proof-dir/registered
tests/e2e/mldsa-registered-proof.sh verify proof-dir/first proof-dir/second proof-dir/state proof-dir/registered
```

The Rust/native RocksDB prerequisites and version-1 first-graph manifest support
are the same as above. Inputs contain self-created public development accounts;
no RPC, funds or retained private key is needed. Existing source, signature,
address, ID and Embedded-leaf proofs are reused after checking their exact native
preimages. Only changed MPT hashes and the Reference leaf require new proofs.
The verify command generates no proofs, and every stage exits nonzero on failure.
Keep generated databases and checkpoint files together; partial fixture recovery
is not qualified and existing records are not overwritten.

Six cases combine original legacy-key, retained-address legacy-key and
retained-address tagged-key accounts with Embedded and Reference modes. Each
verified proof supplies crypto verification to actual native admission and
candidate-block import validation. A separately initialized local genesis,
registry and explicit configuration supply the trusted policy context. The
regression executes a real transfer, checks the receipt, nonce, sender fee/value
debit and full-address recipient balance, commits it, closes RocksDB and reopens
the receipt and current/historical roots. Saved execution records bind the exact
transaction witness, public key, parent account/root and configuration. Resume
checks this binding and read-only native import policy before reopening state;
foreign saved records fail. A shared local storage column permits
one overlay commit for this fixture's account/registry/receipt writes. A batch
that executes its first transaction and then fails nonce validation discards
all staged writes. Refusal controls use actual missing/conflicting registry
entries, default-disabled and pre-activation tagged keys, plus altered proof/source inputs.
Actual MPT snapshots for absent, unbound and custom-validator accounts must
fail this bounded profile. An insufficient-funds first-use transaction must
fail without registering its key.
The missing-registry original Embedded case instead verifies native first-use
registration; failed controls must not change the base database.

Design decision: keep cryptographic key binding and native policy separate,
reuse the native `Verifier` interface and transaction executor, and add only a
development dependency on the runtime for the regression. No new registry root,
consensus carrier, gas rule or activation schedule is introduced. Retained-address
state fixtures do not prove a key-rotation transaction lifecycle. Candidate
import validation and isolated transaction persistence do not establish full
consensus block import/replay or block reward settlement. Automatic node wiring,
canonical historical registry authentication, other algorithms/AA/private proofs,
public release and network activation remain separate acceptance.


## Trusted canonical parent context

`ChainStore::canonical_parent_view(expected_tip, expected_parent)` selects a
retained parent under an independently trusted local tip. One bounded consistent
snapshot captures the head, configuration schedule, address-keyed metadata,
canonical number mappings, selected headers/bodies/witnesses and undo journals.
It checks header hashes, contiguous ancestry, canonical mappings and the stored
genesis identity before rewinding native address metadata privately. The limit
is 128 blocks and 64 MiB; every rewound block needs its retained body and complete
undo journal, including an empty journal when no address metadata changed.
Unavailable history or snapshot support fails without using current keys.

The result exposes a sealed read-only store. Callers cannot commit it, alter
frozen keys, or resample live mutable namespaces. Content-addressed trie-node
reads remain backing-store reads; pruning them can cause an availability error.
The captured configuration schedule is applied at the requested validation
height; address metadata, rather than configuration history, is rewound. This
is a bounded native validation view, not a general historical database export.

`verify_canonical_registered_signature` resolves the account and registered key
from this view and verifies the complete existing registered signature proof.
It binds the result to the captured tip and parent, rejects a foreign chain ID,
unsupported outer framing and oversized signing sources, and builds expected
native IDs without copying a caller's cached transaction hash. A key first
registered after this parent cannot authorize the registered-only profile there.
First-use Embedded transactions retain their separate derived-address/native
validation path. Native nonce, funds, activation and lifecycle policy must still
run against this same view before using the result.

After the preceding producers, run:

```bash
tests/e2e/mldsa-canonical-proof.sh prove proof-dir/first proof-dir/second proof-dir/state proof-dir/registered proof-dir/canonical
tests/e2e/mldsa-canonical-proof.sh verify proof-dir/first proof-dir/second proof-dir/state proof-dir/registered proof-dir/canonical
```

The Rust/native RocksDB prerequisites and graph-manifest support are unchanged.
The fixture uses the two existing genuine public signatures. Native validation
and execution produce two actual transfers, persist their roots, receipts,
canonical storage records and native undo journals, and reopen them in separate
processes. The first key starts absent and is registered by its first Embedded
transaction; the second key is already registered and its transaction uses
Reference mode. Verification proves the second account at the first block's
root even after its current nonce advances, and rejects the later first-use key
at genesis. It checks native import policy with the proof-backed verifier,
frozen key/head/configuration behavior, refusal controls and unchanged base KV.
Only changed account-path hashes and the second Reference leaf need new proofs;
valid source/signature certificates are reused. Every stage exits nonzero on
failure, and verify generates no proofs. Keep the native database with its
checkpoint files; incomplete fixture recovery remains unqualified.

This establishes authorization context from a **trusted local canonical store**.
The transaction remains an independently expected input. It does not prove
network consensus, canonical block-body membership or a key-rotation lifecycle.
The current native producer leaves transaction/receipt roots zero; a header
alone therefore does not authenticate these transaction bodies. The fixture
stores runtime results through canonical storage APIs and does not claim full
node consensus import or block reward settlement. No new commitment, carrier,
gas policy or activation schedule is selected by this view. Cryptographic chain
membership, full node integration, broader profiles and public activation
remain open.

Design decision: reuse atomic prefix snapshots, native metadata undo and the
existing crypto proof/runtime interfaces. Seal the finished view behind a
read-only adapter so successful historical validation cannot write canonical
state or substitute live registry/configuration values.
