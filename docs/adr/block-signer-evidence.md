# Retained block signer evidence

## Context

`shell_getBlockSigners` promises the signer identity, public key and signature
validity for a stored block. Proposer seals live in block bodies, which may be
pruned. Commit certificates contain signatures but do not retain public keys.
The live authority key lookup cannot establish which key authenticated an older
block after that lookup changes.

## Decision

Capture the public key and signature used by authenticated production, import
and quorum finalization. Store versioned binary records under a private index
keyed by block hash and signer address. Separate signer keys avoid replacing
proposer evidence when quorum evidence is added. Stage records in the existing
canonical import overlay or the same batch as side-fork storage, certificates
and the finalized cursor.

The index does not enter the state root, block header or consensus message.
The query resolves a canonical header once and verifies the actual proposer or
certificate signature over that captured hash, including native address binding.
Historical cryptographic validity does not depend on permission to submit new
transactions with the algorithm today. It does not assert current validator
membership or independently validate quorum weight.

For older data, an intact proposer seal or retained certificate can be checked
only with an available key whose native identity matches the signer. Missing
historical keys or proposer evidence produce an error. The query never invents
a successful verdict or substitutes a different live key.

## Consequences

Authenticated records remain available after body pruning and process recovery,
at the cost of retaining public signing evidence alongside headers and
certificates. Existing block hashes, signature domains and certificate encoding
remain unchanged. This does not introduce a consensus key rotation policy or
change algorithm activation rules. Published binaries must include the method
before clients can use it.

The node regression covers genuine Dilithium3 and ML-DSA-65 production, independent
import, finalization and HTTP queries; a RocksDB child process checks fresh-process
recovery. Storage fault injection checks batch atomicity. Algorithm deprecation,
changed live keys, missing legacy evidence and signature tampering are checked
without writing chain state during queries.
