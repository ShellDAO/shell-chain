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
1–16 registered default-account ML-DSA-65 sender profile after body-commitment
activation. Native proposer consensus, body commitments, economics, witnesses,
execution, rollback and canonical parent checks still apply. Unsupported
profiles follow existing native admission; a selected proof-backed candidate's
proof failure does not fall back to native sender verification.

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

For equal registered ML-DSA-65 keys at the same sender position or proposer role,
the next job may borrow public-key decoding, matrix expansion, scaled public-key
NTTs and public-key hashing certificates. Every borrowed certificate runs its
ordinary full AIR verifier against the new job's inputs before publication.
Signature/message-dependent graphs, account witnesses, transaction identities
and headers are always bound to their own source. A donor status is informational;
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
