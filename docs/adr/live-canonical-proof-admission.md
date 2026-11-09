# Live canonical sender-proof admission

Status: unreleased, opt-in implementation.

## Context

Complete sender graphs can exceed ordinary block and amendment frames. An
already canonical block can be replayed with a downloaded graph, but a fresh
follower needs an independent current parent before it can accept that block.
A producer's completed job and a cache's verified flag are never authorization.

## Decision

At ordinary `NewBlock` and `BlockResponse` intake, a separately enabled follower
stages an eligible signed extension as an untrusted immutable local source.
Keep at most two retained bodies, each at most 2 MiB. Admit only the existing
1–16 supported default-account ML-DSA-65 or bound genuine PQClean Dilithium3
sender profile after body-commitment
activation. Native proposer consensus, body commitments, economics, witnesses,
execution, rollback and canonical parent checks still apply. Unsupported
profiles follow existing native admission; a selected proof-backed candidate's
proof failure does not fall back to native sender verification.

Registered Dilithium3 uses sender profile 3, transaction/signature proof version
2 and a separate version-2, 32-byte-seed challenge AIR domain. It authenticates
the locked PQClean raw transcript, including all 48 c-tilde commitment bytes;
it does not relabel an ML-DSA certificate. Native tag-zero SDK compatibility,
unbound Dilithium3 and Dilithium3 proposer proofs remain outside this profile.
The Native transcript check only selects supported candidates; the complete
proof verifier has no Native signature fallback. Existing proof versions,
defaults and activation schedules retain their meaning. See the runnable
[Dilithium3 regression](../stark-aggregation.md#genuine-pqclean-dilithium3-sender-proofs).

Use authenticated Identify protocol advertisements to select discovery peers.
Offer `/shell/canonical-proof/2` alongside the existing chunk protocol version 1.
Only peers advertising version 2 receive manifest discovery or availability
frames. All these messages stay on the dedicated bounded unicast transport;
there is no gossip fallback. Bind discovery replies to peer/block/nonce, and
bind chunks to their existing persisted peer/manifest/index/nonce. Unsolicited
availability can only select a matching staged body after native source checks.
Retain the existing 512 MiB raw cache and immutable corruption generations.
Allow two distinct manifests per candidate and one hash-corrupt recovery;
rotate discovery among connected compatible peers without retrying the same
cryptographically rejected manifest. Retained failures consume capacity.

One blocking worker verifies full AIR against the independent native parent.
It can send only an opaque verified result to the serialized node event loop.
That loop rechecks parent and body context and invokes the native atomic
importer. The worker never writes canonical state. Shutdown joins a running
worker and releases its claim without committing its result. Restart rechecks
all cryptography, including when local metadata says verified. If native commit
preceded status persistence, recover through canonical replay and receipts;
do not replay execution or emit a second import event. After either a fresh
commit or recovered canonical completion, explicitly request the next native
height. A generic periodic probe begins at finality plus one to discover missing
certificates; on an unfinalized chain it can repeatedly retrieve an older
ancestor instead of continuing past the proof-backed child.
An unfinalized requested suffix arrives through normal `NewBlock` validation,
followed by an empty response for its original nonce. After that exact requested
height advances the native head, request the next height with a new nonce so
the older empty response cannot end synchronization. Unsolicited announcements
do not trigger this continuation.

## Limits

This is a bounded experimental extension path, not general fork, amendment,
key-registration/rotation or AA proof consumption. Proposer cryptography remains
native. It introduces no settlement reward, fee, consensus schedule or activation
change. The retained-body cap and large raw graphs limit throughput; there is no
automatic eviction. Public release and network activation require separate
acceptance. The live peer regression is linked from the STARK guide.
## Sustained peer regression

The same two real nodes continue after the first admitted child. Enable automatic
production on the provider with no component budget, recheck the retained second
job's certificates and generate its remaining mathematical graph. Ordinary peer
intake imports that distinct signed child and then the signed empty suffix to
local height 130. The test holds the suffix explicitly while it replays the
complete second graph against native head 2 without writes. Cold final checks
compare every native body, canonical hash, receipt and latest account; history
outside the existing 128-block bound is an expected refusal, not a successful
historical proof. This exercises two eligible sender blocks within the retained
job/cache limits; it does not establish indefinite capacity or throughput.

The separate gossip assertion starts from independent genesis and an empty
proof cache. A test transport suppresses direct block bodies and periodically
broadcasts the genuine signed block through libp2p gossip; it does not change
production node validation or proof transport. The broadcast timer persists
across cancellation of `next_event` by the node event loop. Accepted source
hash, receipts, accounts and two cold read-only proof replays must agree with
native execution. This distinguishes actual broadcast intake from an
unfinalized block returned directly in response to a sync request.

## Full proposer signature profile

Payload version 1 retains its exact sender-only encoding and native proposer
cryptography. Version 2 requires the existing full `ProposerSealProof` alongside
all ordered sender proofs; a missing seal, a seal attached to version 1, or an
unknown version is rejected. The transport manifest remains version 1 and still
describes opaque bounded bytes. Both peers need a consumer that understands the
version 2 payload. Existing default-off production/admission flags and native
activation parameters are unchanged.

For a native ML-DSA-65 proposer, automatic capture freezes its public key and raw
seal as version 2 inputs. Restoration checks retained native block-signer
evidence rather than resampling a later authority key. The same checkpoint store
generates and rechecks the raw header-hash signature graph plus header hashing;
one untagged sender and proposer use 118 components. Existing 256 MiB checkpoint
and payload limits remain, so this is a bounded profile, not indefinite capacity.

Workers return an opaque exact-tuple proposer verifier only after full AIR
verification. The serialized native import loop still selects the authority,
loads its key, verifies header/timing/quorum rules and executes economics and
transactions atomically. Only the final seal cryptography uses the matching
proof token, with algorithm policy checked under the native parent registry.
Changed key, header, seal or chain context has no native-crypto fallback. A
reported `proved_proposer_signature` result is informational and cannot create
an authorization token.

The full regression uses fresh ML-DSA-65 sender/proposer keys kept in memory,
automatic capture, a real shutdown/restart checkpoint, peer transfer and native
import. It also replays the historical full proof after a separately labelled
ordinary native successor changes current balances and nonce. That successor
is a history control, not a second proof-admitted block. Bad proposer AIR with
a correct outer hash and genuine raw signatures, invalid envelopes and an
unauthorized header must refuse without native writes. Full validator-selection
AIR, other proposer algorithms, multi-sender load and full fork/amendment
acceptance remain separate work.

## Consecutive full jobs

For equal registered ML-DSA-65 keys across sender positions or the proposer role,
a later position or job may borrow public-key decoding, matrix expansion, scaled public-key
NTTs and public-key hashing certificates. Every borrowed certificate runs its
ordinary full AIR verifier against the new job's inputs before publication.
Signature/message-dependent graphs, transaction identities and headers remain
bound to their own source. An account witness is shared only for the identical
parent state root, sender address, encoded account and native MPT witness nodes;
subsequent account changes require a new proof. Native execution still checks
ordered nonces and state changes for every transaction. A donor status is informational;
it cannot create a verified token or bypass native source restoration.

Old inline certificates remain immutable and readable. Equal certificate bytes
in a later job use a versioned one-hop reference to an indexed retained job's
inline component, with exact length and hash checked on reads. Missing, changed,
malformed, chained or cyclic targets fail closed. The component index, reference
and physical quota counter are committed in one storage batch. The per-job logical
bound and global physical checkpoint bound stay 256 MiB; the two-job limit and
separate 512 MiB proof transport cache also stay unchanged. This adds no eviction
or indefinite retention policy. Reading new reference records requires a reader
that implements this storage format; older inline source/proof encodings are
preserved, not rewritten.

`tests/e2e/mldsa-full-proof.sh consecutive output` continues a completed full-run
output using its retained genuine signed second block and public certificates.
It reconstructs a fresh genesis receiver, proves and imports both full targets,
compares native execution/finality and cold-replays both proofs without writes.
For this single-authority fixture, the retained proposer's genuine block-hash
signature is also submitted as a vote on the identical hash; no private key is
recovered and no new signature is fabricated. A real shutdown/restart rechecks
shared and local checkpoints. A separate damaged-reference copy must fail
production without changing the provider's native state even when valid ready
transport payloads remain cached. Independent observers may still accept those
valid payloads; production checkpoint integrity is not a consensus invalidation.


## Ordered full batches and named references

The source matcher returns the exact donor component name and permits only
mathematically input-equal key components or identical account witnesses. Within
a job, only an earlier position can donate, after its durable checkpoint exists.
Every borrowed certificate runs the recipient's full verifier before atomic
publication. No signature, nonce-dependent identity or header proof is borrowed.

Named version 2 local reference records can point to another component name in
the same indexed job or another retained job. If a donor already uses a reference,
the writer resolves and verifies it, then points directly to its immutable inline
anchor. Reads validate the owners, bounded component name, exact length and hash;
self-references, missing anchors, chains and cycles refuse. Existing inline and
version 1 same-name cross-job records remain readable and are preserved exactly.
This is a local checkpoint format change; the full proof wire format stays at
version 2 and the logical/physical quotas and job/transport bounds stay unchanged.

`tests/e2e/mldsa-full-proof.sh batch output` creates fresh memory-only test keys
and two transactions from one registered sender in each block. It pauses and
reopens real production, generates two 179-component full graphs, and sends them
through real peer admission. A fresh genesis receiver must execute and finalize
the valid ordered batch, matching independent native receipts, balances and nonce.
Key mathematics and identical within-parent account witnesses are reverified and
shared rather than regenerated at the second position or next job.

The second source is explicitly a Byzantine storage fixture: its genuine sender,
proposer and single-authority quorum signatures cover a wrong state root. It is
not claimed to have passed native execution. The independent correct second
block is produced by actual native execution. Only after the valid first block
has finalized does the transport fixture release the bad child. Admission must
reach both native transaction executions and reject the wrong resulting root,
leaving all native trie, index, receipt and finality rows unchanged. Proof/cache
metadata may record the failed attempt; a valid signature proof does not establish
state-transition validity. The correct second block is then imported separately
through ordinary native verification, and cold historical full-batch replay must
match original outputs without writing any current KV data. This control is not
claimed as a second proof-admitted target. Full 16-transaction load, arbitrary
sender/key layouts and unbounded job retention remain unqualified.


## Bounded compact availability for larger jobs

Raw JSON repeats public-key mathematics and encodes opaque STARK bytes as decimal
arrays. New jobs with more than two transactions use a versioned compact component
encoding and a certificate pool in their ready payload. The already locked CBOR
serializer is reused; this adds no new mathematical primitive or recursive proof.
The native block, genesis, signing messages and proof statement versions do not
change. Existing one/two-transaction jobs still emit their exact legacy JSON;
readers accept both availability formats.

Compact checkpoints have index version 2. Input-equal earlier positions use their
existing canonical checkpoint name rather than publishing another logical copy.
The recipient still runs the complete verifier against its own expected inputs.
Only the source-derived equal-key/identical-account map can choose those names;
message, signature, nonce, transaction identity and header dependencies remain
separate. Existing jobs retain their original index, bytes and accounting when
reopened, including old inline and direct references. No legacy large-job migration
or data eviction is implied. Progress reports distinct stored components while
reverification counters include every recipient verification.

The compact wire prefix identifies format version 2 independently of the inner
version 1/2 signature statement. Each pooled object contains an entire ordinary
mathematical certificate, with named proof byte vectors packed as byte strings.
The template points directly to immutable pool indices. Content hashes check
integrity and deduplication only; decoding creates an unverified typed statement.
Native callers still run complete AIR, account/key/algorithm/nonce policy,
consensus and atomic execution. Framing or a reported verified flag cannot supply
an opaque verification token.

The decoder rejects unknown versions, duplicate/changed/unreferenced pool entries,
missing or malformed references, chained references inside certificates,
noncanonical encodings, duplicate map fields, trailing bytes and unsupported
values. It bounds encoded bytes, nesting, templates, individual certificates,
pool counts, reference counts and expanded data before native publication.
The existing 256 MiB payload/per-job/global checkpoint limits, two-job retention
and separate 512 MiB cache remain unchanged. Older readers require a compatible
build for the new encoding; they must not silently use native signature fallback.

`tests/e2e/mldsa-full-proof.sh wide output` is the fresh sixteen-transfer regression.
Its independent genesis funds one temporary registered ML-DSA-65 sender with
2,000,000 test units and uses a distinct ML-DSA-65 proposer. Signing keys exist only
in preparation memory. The good block must produce 17 receipts, gas 336,000,
nonce 16 and independent roots/balances, then finalize through actual peer intake.
The genuine signed wrong-root successor must reach all sixteen VM transactions
and refuse with unchanged native KV rows. A separately labelled correct ordinary
successor reaches nonce 32; historical full replay must not change current data.
The larger experiment's idle observation window is separate from protocol timing.
Keep all data and receipts across pauses. Distinct-key/witness layouts, full load,
other algorithms and public release/activation remain separate qualifications.
