# Complete SHA2 compression certificates

Status: accepted for unreleased compression primitives; full SLH integration remains unfinished.

## Context

Native SLH-DSA-SHA2-256f requires both SHA-256 and SHA-512. Native signature
verification cannot stand in for a mathematical proof of those hashes. A
compression backend also needs to reuse verified public-seed prefix states and
amortize proof overhead across independent blocks.

## Decision

Prove each complete message schedule, 64/80 rounds and eight-word feedforward.
Fixed public routing selects operands and certificate results. The AIR checks
every Boolean operation, rotation/shift and modular addition; verification does
not compute a native SHA digest. Callers supply independently expected chaining
values and blocks rather than trusting inputs claimed by a certificate.

Represent both algorithms with constrained 32-bit limbs over Goldilocks.
SHA-512 additions connect their low and high limbs through proved carry bits.
Split every 64-bit public word into two field elements, because direct field
reduction would alias valid values at or above the Goldilocks modulus. Use a
fixed quadratic-extension profile with the existing query, blowup, grinding and
FRI settings. Other proof profiles and global defaults are unchanged.

One certificate covers up to sixteen independent compression inputs, with
bounded operation/carry vectors and proof bytes. Serialize the exact algorithm,
ordered inputs, operation results, carry bits and STARK proof. Reject unknown
versions, wrong inputs, malformed shapes, wide SHA-256 words, a different trace
layout or proof options. The public certificate example refuses output
replacement and trailing serialized data.

## Consequences

The bound is a proving resource profile, not a transaction or protocol limit.
Input capacity does not imply measured performance at every batch size. Padding,
digest chaining, FIPS 205 address/message routing, FORS, WOTS+, hypertree,
canonical authority and durable node/peer/history integration remain separate
requirements. A compression certificate never becomes a verified signature
token by itself. Existing canonical source formats retain their meanings.

The focused regression uses independent RustCrypto compression/digest results,
real STARK batches, carry and field-modulus boundaries, counterfeit operator
outputs, serialization and malformed/public-input/proof refusals. The separate
`sha2-compression` example proves a certificate and verifies its physical output
in another process; see the executable commands in
[STARK aggregation](../stark-aggregation.md#native-slh-dsa-fallback-and-canonical-proof-reproduction).
