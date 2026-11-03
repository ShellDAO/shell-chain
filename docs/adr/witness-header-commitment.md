# Optional witness commitments during production

## Context

Headers, witness RPCs and block import already support an optional witness root,
but production always leaves it absent. Retaining signatures separately from a
block body therefore cannot establish a match against a header commitment on
blocks produced by the node.

## Decision

Add the default-off `--commit-witness-root` operational option. For a block with
user transactions, compute the existing witness root after selecting and executing
transactions and before proposer signing, block hashing and canonical storage.
The stored witness bundle follows exactly that user-transaction order. System
transactions do not add user witnesses. Empty and system-only blocks retain an
absent root because they do not store a witness bundle.

Keep the existing commitment algorithm: each leaf is Keccak-256 of the canonical
RLP witness `[[algorithm_tag, signature], public_key_or_empty_bytes]`. Tags are 0
for Dilithium3, 1 for ML-DSA-65 and 2 for SPHINCS+-SHA2-256f. A parent hashes the
concatenated 32-byte children; duplicate an odd final child at each level. An empty
bundle's computed root is zero. This changes neither the algorithm nor header
encoding. Existing import verification rejects a present but mismatching root
on both canonical and side-fork paths.

## Consequences

The option can be enabled or disabled between process starts. Stored headers
remain immutable and historical roots remain queryable after restart. Legacy
headers and mixed producers without commitments remain valid; this is not a
chain-wide requirement or activation schedule. The option changes newly produced
block hashes and seals only when a user witness root is included. Operators must
use peers that support the existing optional header field and verify compatibility
before enabling production. Witness pruning and STARK settlement remain governed
by their existing policies; a missing bundle cannot produce a successful match.

The native witness acceptance checks genuine ML-DSA transactions and independent
RLP/Keccak computation across producer, importing peer and process restarts. It
does not establish light-client consensus verification, Byzantine fault tolerance
or public release availability.
