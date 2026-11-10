# Separate large native envelope proof profile

Keep native commitment encodings and canonical transaction IDs unchanged. The
transaction ID hashes a fixed 80-byte domain/sender/signing-hash preimage and
excludes authentication witnesses. The body leaf includes the complete native
signed envelope, which can exceed the existing 16 KiB proof bound with an
SLH-DSA-SHA2-256f signature.

Add an explicit 64 KiB BLAKE3 hash v3 and body-membership v2. Preserve legacy
hash v1/v2 bounds and membership v1 semantics. Each independently routed
compression must verify against a concrete AIR certificate before its result
can feed chunk chaining or parent/root hashes. The final membership binds
ordinary index, ordered siblings, odd carry, leaf count and the independently
selected header transaction root. Providers cannot supply trusted digests.

An envelope certificate binds that large body leaf together with the existing
small signing-payload and transaction-ID hash proofs. A signature mutation may
leave the ID stable while failing membership; neither identity nor membership
alone establishes signature/account/consensus authority. Do not use native
BLAKE3 as proof acceptance. Native references are confined to input export,
prover consistency checks and regression oracles; header hashing only labels
the membership result.

Persist immutable public inputs and verified compression/hash checkpoints.
Permit retained concrete checkpoints, verify every consumed one and refuse
replacement or corrupt data. Keep complete certificates separately readable
for cold verification. A development aggregate reader may use a separate
bound without increasing native limits, gas, global store quotas, default
activation or changing canonical source formats. Production source/jobs,
signature binding and peer/history acceptance require their own integration.
