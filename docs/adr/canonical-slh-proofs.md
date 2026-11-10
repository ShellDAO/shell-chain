# Registered SLH canonical proofs and bounded availability

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
