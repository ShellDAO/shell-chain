# SLH default-account proofs and bounded availability

The complete SHA2-256f signature graph and its large native signed-envelope body
must authorize the same historical sender. Standalone FORS/XMSS or body proofs
cannot establish account authority, proposer permission or successful execution.

Use explicit source format 6 for one bound default-account sender with a
parent-registered 64-byte key, the original 49,856-byte signature and a supported
independent registered proposer. Batch profile 3 contains that complete sender
graph plus the mandatory existing proposer proof. Verification resolves the key
from the frozen historical parent, verifies the account MPT and raw/tagged key
commitment, binds the signing payload and unchanged canonical identity to the
full envelope/header, verifies FORS and every hypertree layer, and verifies the
native batch-entry leaf. Only then is a private exact-tuple verifier constructed.
Native execution still enforces lifecycle, permissions, nonce, economics,
consensus selection and commit/rollback. The new framing does not authorize a
new consensus algorithm or activation height.

Raw compact checkpoints of the genuine signature/body graph exceed the existing
256 MiB job quota. Preserve failed intermediate jobs; never increase that quota
or rewrite an existing index. New checkpoint format 4 uses component format 2.
These omit only deterministic SHA2 operation/carry vectors after checking exact
equality with the native prover's witness reconstruction. The decoder recreates
the complete original public statement, including every operation and carry.
The unchanged cryptographic proof bytes and full AIR must still verify. A changed
input changes that reconstructed statement and fails the original AIR; native
witness generation never grants verification authority or supplies a successful
hash/signature fallback. Noncanonical vectors cannot be silently replaced during
encoding. The old full 8 MiB component ceiling also applies after reconstruction.

Availability frame 4 streams the sender's bounded hash/layer/group certificates
rather than constructing a single enormous JSON number tree. Canonical groups of
at most sixteen BLAKE3 compression certificates reduce dictionary slots. SHA2
witness compression reduces stored bytes while retaining all mathematical
certificates. The existing 256 MiB payload and 2,048-certificate ceilings remain;
one large sender and its proposer share the existing 1 GiB expanded-pool budget.
Old frames retain their prior bounds and byte encodings. Decoding alone never
creates a verified token or skips a proof, even for a durable cache hit.

The source-build regression uses retained original Native signatures and proof
graphs, a genuine durable budget pause, cold verification and actual Node
execution. Its separate RocksDB receiver is explicitly reconstructed at the
original genesis from authenticated trie nodes and historical registrations,
without copying child execution or receipts. This is direct offline import,
not evidence of peer transport, quorum/finality AIR or history after an original
signed successor. Automatic production, broader combinations and public release
and activation require separate acceptance. No power-loss claim follows from a
clean component-budget pause.

The warm-checkpoint automatic regression separately exercises ordinary Native
import capture, actual background-worker cancellation/restart, complete AIR
revalidation and authenticated loopback chunk retrieval. Its isolated fixture
transplants a completed same-source checkpoint and retains the queued status;
the worker supplies the verified result and ready payload. It requires zero new
mathematical certificates and no signing capability. A separate corrupt copy
updates the component hash and accounting around damaged proof bytes, so a
failed background verification cannot be mistaken for a storage-hash mismatch
or accepted through an existing ready payload. This experiment leaves fresh
automatic generation and later-original history open.

Live proof admission uses the same bounded sender-shape preflight as production
for the registered SLH profile, with its supported independent proposer and
historical 64-byte key. Ordinary block responses stage that child before Native
import. An attached next-height quorum certificate is independently verified
and retained while the proof is pending, then reverified against the canonical
target after successful import. A pending or rejected proof cannot finalize
the child through that certificate.

The real TCP/Noise regression transfers the original ready frame to a separate
genesis-only receiver, pauses after three chunks, resumes in another process
at the missing chunk with a fresh nonce, and checks Native execution and
certificate-backed finality. Its provider restores the original signed quorum
certificate through the normal verification API; the receiver receives no child
state or finality. Cold replay checks the received graph without writeback.
Standalone certificate messages are withheld so this regression specifically
requires the ordinary block response's attached certificate to survive staging.
A correct-hash payload with a genuine certificate in the wrong statement slot
must fail even with genuine original signatures and a valid quorum certificate.
This covers the original first child and single authority, not quorum AIR,
later-original history or public release and activation.

Fresh automatic generation has a separate standalone regression. It captures
the original signed child through ordinary Native import with an empty
mathematical job and no availability cache, without requiring or opening a
completed reference checkpoint. The actual worker must generate nonzero new
certificates, persist a graceful budget pause, cold-resume with full verification
of retained progress, and generate the remaining graph within unchanged quotas.
Authenticated RPC retrieval and cold read-only Native replay establish the
generated output; a separate peer receiver checks execution and finality.
Warm-checkpoint revalidation alone cannot satisfy these fresh-generation checks.

Funded first use has a separate source format 7 and SLH transaction proof
version 2. The historical parent must contain a default account with a zero
key commitment. Its first Embedded public key must derive the sender address
as BLAKE3 of the algorithm tag and all 64 key bytes; a complete address AIR
certificate is mandatory alongside the unchanged full signature graph, account
MPT, envelope, identity, body and proposer certificates. Source 6 and transaction
proof version 1 retain bound-account authority and reject this substitution.
A registered historical key takes precedence; a future key cache is never
historical authority. Missing accounts and custom validators remain outside
this profile.

Native intake validates first-use signatures without registering the key.
Proof-backed commit performs the ordinary key registration; rejection and
historical replay cannot write that registration. Existing funded accounts can
retain their zero account commitment after registration. First-use proofs must
therefore follow the sealed parent account and registry, not infer a nonzero
commitment from the current cache. The regression advances an independent
Native control and proof receiver to a genuinely different second state and
replays the first child against that historical parent without writeback.
Its retained SLH signature is reused in an independent genesis with a new
proposer; this does not create a missing successor in the original bound history.

The automatic regression reconstructs registrations from the sealed parent.
A missing sender key is valid only for the funded default-account first-use
profile with a matching Embedded key and derived address; a missing proposer
key remains an error. The ordinary Native import must register that sender and
capture source 7 with zero mathematical components. Fresh mode opens no proof
donor and the background worker must generate the graph itself. A valid warm
checkpoint is a different experiment. The cold first-use check advances an
independent copy to the retained later state, then verifies the generated graph
against both that copy and the ordinary Native later control without writeback.
The original worker output and signed inputs are preserved.

Registered SLH proposer seals use a separate source format 8 and batch profile 4
with one bound primary ML-DSA-65 sender. The sender's existing complete graph is
unchanged. The proposer graph binds the exact canonical header hash to its raw
32-byte message and the historical registered 64-byte key, and verifies the
49,856-byte SHA2-256f signature through FORS and all seventeen hypertree layers.
Only full verification constructs the existing private exact-tuple proposer
token. Native selection, lifecycle, execution, rollback, quorum and activation
remain external requirements. Legacy source 1 can retain sender-only proofs;
it must not be promoted to a full proposer claim by version relabeling.

New availability frame 5 streams this proposer graph through the existing
bounded certificate dictionary and deterministic witness reconstruction. Its
sender and proposer share the existing expanded-pool budget. Checkpoint 4 and
component 2 remain unchanged; no component, pool, dictionary, job or payload
limit increases. Old frames reject the new role rather than silently decoding
it as an optional extension. The independent Native regression creates and
retains actual signed first/later controls once, cold-resumes fresh mathematical
generation, imports with full proofs, and checks historical replay and refusal
without state writeback. The peer regression reuses that ready frame and checks
three-chunk pause/cold resume, proof-backed import, separately verified attached
certificate finality, cold replay and genuine wrong-statement refusal. Both SLH
roles together, broader account profiles, quorum AIR, public artifacts and
activation require separate acceptance.

The automatic entry selects the existing bounded witness encoding for either
supported large-signature role. A valid Source 8 proposer must not be excluded
merely because its sender uses ML-DSA rather than SLH. Ordinary import captures
an empty job; fresh mode opens no donor, and the actual public-only worker
generates, checkpoints and cold-resumes the full graph before publishing
availability. Cold changed-state replay compares sealed sender and proposer
registrations with the original Native parent for both supported history
profiles. First-use history still requires an absent parent sender key; the
bound primary sender in Source 8 requires its original registered key. Neither
can acquire authority from a future current cache. Independent Native later
controls, full-role replay, no-writeback checks and generated-output peer
admission remain necessary; warm revalidation alone proves no fresh generation.

Primary sender first use with an SLH proposer has explicit source format 9,
batch profile 5 and availability frame 6. Its historical default account has a
zero commitment. The existing complete primary first-use signature profile
proves BLAKE3 of the algorithm tag and all 1,952 public-key bytes as the sender
address, alongside account authority and unchanged signed identity/body. The
full raw-header SLH proposer graph remains mandatory. Bound Source 8 and batch
4 retain their nonzero-commitment requirement; neither profile may be relabeled
to substitute the other's parent authority or omit an address certificate.

Frame 6 streams the same bounded proposer dictionary and shared expansion pool,
with the explicit first-use batch version. Frame 5 remains bound-profile only;
older frames retain their encodings and bounds. Native intake does not register
the sender; successful Native commit does. A later current cache must not supply
authority at the first block's sealed parent. Independent Native controls retain
the original public primary signatures through Reference-to-Embedded intake,
first import/registration and a genuine second state, with a new memory-only
proposer for the new headers. Full proof import, no-writeback historical replay,
partial/cold peer recovery and genuine wrong-statement refusal are required.
No existing sender or proposer key is recreated after it is dropped. The fresh
automatic entry restores an absent sender registration only for the validated
funded first-use source and its exact tagged key shape: source 7 has a 64-byte
SLH sender; source 9 has a 1952-byte primary sender and a registered SLH proposer.
Ordinary Native import must capture a zero-component source 9 job and perform
first-use registration. The public-only worker must generate the full frame 6
graph after a durable pause and cold continuation, with no proof donor or new
signatures. Authenticated RPC retrieval, sealed-parent historical replay after
state 2, correct-hash damaged-checkpoint refusal and actual peer import remain
part of this entry's acceptance. Broader combinations require separate checks.

Source format 10, batch profile 6 and streamed frame 7 cover one bound
published-SDK Native tag-zero FIPS sender with a registered SLH proposer. The
captured sender must select SDK transcript marker 1, use `Dilithium3` as its
Native tag and have a nonzero default-account parent commitment. Its existing
account/signature profile 5 requires SDK transaction source 3, complete FIPS
signature/challenge profile 1 and the 48-byte challenge seed. Raw PQClean
transcripts and primary-tag transactions cannot be relabeled into this profile.
The proposer retains the complete raw-header SHA2-256f graph and sealed-parent
64-byte key; no Native verification fallback supplies a missing AIR role.

The Native preparation consumes an existing published-SDK control's first and
later signed transactions, without creating another sender key or signature.
Only the independent SLH proposer keys are created in memory for the new
headers and quorum controls, then dropped. Complete proof import, changed-state
no-writeback history, durable recovery, real peer import/finality and genuine
wrong-header-certificate refusal are required. Frame 7 uses the existing bounded
dictionary and shared expansion pool. Sources 1–9, frames 1–6, default-off
production, Native compatibility and all quotas remain unchanged. Bound raw
Native tag-zero senders use the distinct Source 12 profile below.

The Source 10 automatic entry consumes the same retained Native control through
ordinary import, starting with zero mathematical components and no donor. Its
public-only worker must generate durable progress and cold-resume the full
frame 7 graph. Authenticated RPC retrieval, unchanged Native state, registered
sealed-parent sender/proposer keys after genuine state 2, damaged-checkpoint
refusal and real peer admission/finality remain independent checks. Standalone
proof completion cannot substitute for this empty-job worker flow.

Source format 11, batch profile 7 and streamed frame 8 extend the SLH proposer
case to one funded SDK first-use default account. The Native sender tag stays
zero and the captured SDK transcript marker stays one. Parent commitment zero
requires unbound account/signature profile 6, complete `BLAKE3(0 || pubkey)`
address AIR, SDK transaction source 3 and full FIPS signature/challenge profile 1
with its 48-byte seed. Bound Source 10/batch 6/frame 7 and primary first-use
Source 9/batch 5/frame 6 retain their separate predicates.

Preparation retains the actual public SDK Embedded first transaction and later
Reference transaction byte for byte. Its original node may have advanced;
authenticate the original block in the current canonical chain before restoring
the sealed parent. The new independent SLH proposer signs genuine first/later
headers and quorum controls once in memory, then drops its keys. No future
sender registration is preloaded into genesis. Full Native import must register
the key, and historical replay after state 2 must still see the absent parent
key without writing either current database. Missing/tag-changed address AIR,
SDK/raw/primary relabeling and wrong-slot proposer certificates must refuse.
Frame 8 retains the shared dictionary, expansion pool and existing quotas.
The empty-job automatic entry retains the same Native first/later controls and
starts without a completed proof donor. A durable initial pause must continue
from its existing job; never replace it with another preparation. Actual
public-only worker generation, authenticated frame 8 retrieval, sealed-parent
SDK key absence after state 2, no-writeback replay on both controls,
correct-hash damaged-checkpoint refusal and generated-frame real peer admission
are independent checks from standalone proof completion. Raw first-use
SLH proposer combinations remain open.


For the SDK Reference target after first use, preserve all three original SDK
signed transactions. A separate independent SLH proposer must sign three genuine
headers and quorum controls before its keys are dropped. Save the independently
imported, finalized Native parent at height 1 before advancing either control;
restore that checkpoint for proof import and peer admission of target height 2.
Validate its canonical header/configuration, state root, finality and historical
sender/proposer keys, and reject preloaded target state, receipts or block.

Source 11 remains necessary because the account commitment is zero, even though
the sender key was registered by the prior Embedded transaction. Resolve the
expected key from the sealed parent instead of inferring registration absence
from the unbound account profile. Import and finalize the full Reference graph
at height 2, then replay it read-only after the genuine third block on both
proof-imported and ordinary Native controls. No SDK signatures or existing
proposer identities are recreated. Full fresh automatic Reference-target production has its own empty-job
acceptance entry; standalone completion cannot substitute for it. Public
artifacts and activation remain separate acceptance work.


The Reference-target automatic entry reuses the same independently finalized
Native parent checkpoint as proof import and peer admission. Share its canonical
header/configuration, state-root, finality, key and absent-target validation.
Keep genesis restoration for earlier profiles. Ordinary Native import of target
height 2 must capture an empty Source 11 job, with no mathematical donor or
preloaded target data. The public-only worker must generate durable progress and
cold-resume the complete frame 8 graph. Authenticated retrieval remains
availability only. Validate generated-proof historical replay after the genuine
third block against both current Native controls without writeback, reject a
correct-hash damaged component without retry, and exercise generated-frame real
peer import/finality2/cold/refusal. No Native control or signing input is replaced.


A restored finalized parent requires the genuine target quorum sidecar before
starting the cold worker: ordinary startup deliberately rewinds an uncertified
suffix. Complete that Native consensus step using the original verified quorum
certificate. Existing stopped jobs may reimport the retained target after the
expected rewind and complete its finality without replacing any source or
mathematical progress. Record the completed Native baseline separately and
assert that proving never changes it. Preserve earlier failed attempts. Status
RPC failures after service startup must surface immediately and trigger graceful
Node shutdown; they must not become an unobservable polling timeout.


Keep a distinct status-provenance refusal entry: copy the completed local job,
damage its recorded source hash, then require the real authenticated status RPC
failure to surface and the Node to shut down gracefully. Neither original job
nor Native data may change, and no new signing or mathematical generation may
supply the refusal. This differs from a corrupt inner AIR component whose outer
hash was repaired.

Source format 12, batch profile 8 and availability frame 9 add one bound raw
PQClean Native tag-zero sender with a registered SLH proposer. A nonzero
default-account parent commitment and absent SDK transcript marker are mandatory.
The existing raw account/signature profile 3 and transaction source 2 must prove
full signature and challenge version 2, preserving the first-32-byte sampler
domain and the complete 48-byte commitment. Neither SDK FIPS nor primary-tag
proofs can substitute. Raw unbound senders remain outside this new profile.

Freeze both historical public keys, the exact sender bytes and the genuine raw
SLH header seal. The proposer uses the same full seventeen-layer SHA2 graph as
earlier proposer profiles; no Native fallback fills either role. Frame 9 keeps
the shared dictionary and all existing byte, expansion and certificate limits.
Sources 1–11 and earlier frames retain their meanings, including historical
sender-only source 1. A new explicit format prevents that partial source from
being relabeled as a complete proposer proof.

Preparation consumes two retained genuine raw sender transactions and creates
only the independent memory-only proposer, freezing first/later headers and
quorum controls before dropping its keys. Require durable pause/cold generation,
CLI revalidation without new proofs, complete Native import and finality,
changed-state historical replay without writeback, and actual peer transfer,
cold replay and genuine foreign-header refusal. Raw first use, later Reference
targets, broader accounts/roles and public release or activation require separate
acceptance; defaults and Native admission policy do not change.

The Source 12 fresh automatic entry reuses the same retained Native control and
raw sender/SLH header signatures. Ordinary import must capture an empty queued
job, restoring both historical registered keys without preloading child state.
The actual public-only worker generates nonzero progress, durably pauses and
cold-resumes that same job without opening a completed graph donor. Require
authenticated frame 9 retrieval with no execution-authority claim, Native-state
stability, historical replay after the genuine second block on both controls,
correct-hash damaged-component refusal, and an independent status-provenance
RPC failure with graceful shutdown. The generated graph must then pass real
peer admission, attached-certificate finality, cold replay and foreign-header
refusal. Existing standalone and earlier automatic qualifications remain distinct;
no key creation, Native policy, production default or quota changes follow from
this entry.
