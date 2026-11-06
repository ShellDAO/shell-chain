# Native block commitments

The optional `block_commitment_height` chain rule enables **block-commitment-v1**
from that block number onward, inclusively. Omitting the field preserves the
legacy transaction and receipt root behavior. No public network activation is
selected by this implementation.

The white paper requires BLAKE3 and unambiguous header sealing, but does not
specify the transaction or receipt root byte format. This document defines that
format as a separate native profile. The signature accumulator, transaction ID,
state trie, optional legacy witness root, and proposer seal formats retain their
existing meanings. These roots are native Shell commitments; Ethereum receipt
trie proofs do not apply.

## Byte format

All hashes below are full 32-byte BLAKE3 outputs. `||` denotes concatenation.
`u64be(x)` is exactly eight bytes in big-endian order. Domain strings are the
literal ASCII bytes shown, including one trailing zero byte:

| Header field | Domain | Ordered values |
| --- | --- | --- |
| `transactions_root` | `SHELL_BODY_V1\0` | All signed transactions, then all system transactions |
| `receipts_root` | `SHELL_RECEIPTS_V1\0` | All execution receipts, including system receipts |

For zero-based index `i`, the leaf is:

```text
BLAKE3(domain || 0x00 || u64be(i) || kind || canonical_native_RLP(value))
```

For system transactions, `canonical_native_RLP(value)` is the RLP byte string
containing the existing deterministic struct JSON produced by `to_wire_bytes`,
as in the native block wire format. Keys follow struct declaration order:
`kind`, `chainId`, `blockNumber`, `txIndex`, `from`, `to`, `value`, `sourceHash`,
then optional `layer`, `originalSize`, `compressedSize`, `proofPayload`. JSON is
compact, without whitespace. Addresses and hashes use full 32-byte lowercase
hex strings prefixed by `0x`; values use the native minimal hex quantity
encoding. Absent optional fields are omitted; present
zero values remain present. Serialization errors are rejected.

`kind` is one byte: `0x00` for a signed transaction or receipt, and `0x01` for
a system transaction. Signed transaction RLP includes the full sender address,
transaction, signature algorithm and bytes, embedded key or reference mode,
and optional AA bundle. Using full RLP prevents a witness change from retaining
the body root even though the canonical transaction ID intentionally excludes
that witness. Derivation never reads the cached transaction ID.

Reduce the ordered leaf list pairwise using:

```text
parent = BLAKE3(domain || 0x01 || left_32 || right_32)
```

An unpaired final node is carried unchanged to the next level. Repeat until
one node remains. With `n` original leaves and that final node `top`, the root is:

```text
BLAKE3(domain || 0x02 || u64be(n) || top_32)
```

For an empty list, `n=0` and `top` is 32 zero bytes. The empty commitments are
therefore domain-separated hashes, rather than the legacy zero root. Index,
count, kind and node tags prevent reordering, list-shape ambiguity and
cross-domain substitution.

Receipt encoding is the native `TransactionReceipt` RLP: transaction ID, block
number, index, status, gas used, cumulative gas used, optional full-width created
address, log bloom and ordered logs. It contains no block hash, avoiding a
header/receipt hash cycle. Receipt count and transaction ID/index/height must
match the body, in the same order.

## Execution and persistence

Production computes both roots after execution and system transactions, before
proposer sealing or proof-task identification. Reception checks the body before
classifying duplicate blocks or retaining side forks. Canonical import and
historical replay compare the receipt root with deterministic execution output
before publishing state, keys, receipts, indexes or the canonical head. Reorg
publication checks every replacement block and its receipts.

Body and witness restoration also checks the complete body commitment. Restoring
an activated full body requires its original authentication witness, even when
only the stripped payload will be retained. Existing locally retained pruning
digests remain additional checks. Header authentication and the trusted chain
configuration are prerequisites: a matching root alone does not establish
consensus, finality or signature validity.

The height is persisted with chain identity, restored only against an identical
trusted snapshot schedule, and checked during node startup. An existing stored
schedule cannot be changed or removed. Adding a schedule to an existing chain
requires a future height above the current head. Selecting that height requires
the network's normal upgrade process. Activation at height zero produces distinct
empty genesis commitments and consequently a distinct genesis identity.

## Reproduction

Use the repository's `rust-toolchain.toml` (`stable`) and `Cargo.lock`. The
RocksDB recovery check also requires the native C/C++ build toolchain and
libclang. Local qualification uses Rust 1.95.0, Clang 17 and CMake 4.3.1 on
macOS ARM64; other platforms need their own qualification. The regression entry
point creates test accounts and test funds; it needs no pre-existing key or
public testnet funds:

```bash
tests/e2e/block-commitments.sh
```

A nonzero exit code indicates failure. The regression covers local signed
production, import, persisted receipts and historical replay with activation
boundaries and mutation refusals. These local checks do not establish public
network activation, public binary availability, full signature proof membership
or a replacement for consensus validation.

The optional [full signed-body AIR membership profile](mldsa-transaction-source-proof.md#air-membership-in-an-activated-native-block-body)
uses these exact native v1 bytes. Its separate 16 KiB hash-proof resource profile
does not change this commitment format or activate any network. It still needs
an authenticated header and independent native policy/execution checks.
