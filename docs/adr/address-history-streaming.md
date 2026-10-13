# Streamed address-history index reads

Status: accepted for unreleased node source

## Problem

The documented default address-history query spans genesis through the head.
Rejecting ranges above 10,000 blocks prevents that query on a mature chain.
Removing only the guard would still copy the entire requested address index
for counting and pagination. Deep offsets must not require retaining that index
or a buffer proportional to the offset.

## Decision

Add an ordered, borrowed prefix-range visitor with early termination. MemoryDb
uses an ordered map for native range visits; RocksDB uses bounded iterators.
The trait's compatible fallback delegates to the existing range scan, so other
store implementations can upgrade independently. Streaming memory guarantees
apply to the native backends, not to a materializing fallback.

Count valid forward-index entries directly. For pagination, visit the same
forward index in descending key order and count each block's entries. Retain
only the block/offset/count plans intersecting the requested page. Read those
selected blocks in ascending index order to preserve newest-block-first,
ascending-transaction-index results. Plans and returned hashes are bounded by
the requested page size. No reverse-index migration, persistent counter or
query-side cache write is needed for older forward-only indexes.

Legacy history, v2 exact totals and address summaries share the counter.
Remove their artificial span rejection while preserving integer-overflow,
input-validation and storage-error behavior. Existing RPC page-size limits
remain in effect.

## Constraints

Exact counting remains linear in the matching index rows; this is a query-memory
bound, not a constant-time or production-latency claim. Native visits each use
a backend read view. The multi-read RPC is not an atomic reorganization snapshot;
if selected rows disappear between planning and retrieval, return an error.
Stable replacement/deletion and reopen tests cover the existing index layout.
Transaction-detail retention and block admission remain separate concerns.
No storage schema, consensus rule, signature domain or activation schedule changes.
