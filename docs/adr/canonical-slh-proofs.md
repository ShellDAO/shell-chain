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
No existing sender or proposer key is recreated after it is dropped. Fresh
automatic first-use generation and broader combinations remain separate checks.
