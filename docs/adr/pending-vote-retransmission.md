# Recovering a lost attestation for a pending block

Status: Unreleased.

A validator initially broadcasts its vote through GossipSub. If that message is
lost, two otherwise healthy equal-weight authorities can retain a proposal
without assembling the two signatures required for finality. Reannouncing the
same proposal does not cast another vote because importing it does not advance
the canonical head.

When a peer requests a pending canonical height, return the existing block and
unicast the local validator's already-recorded vote for that exact height and
block hash. Only an active validator with a matching current voting round may
replay its cached signature. Unknown heights, a different round hash, observers,
and rounds without a local vote do not produce an attestation.

This recovers an existing message; it does not sign a new block, change the vote
payload, weaken the strict weighted quorum, or bypass normal certificate
verification. Finalized responses continue to use stored quorum certificates.
The compatibility and activation rules for signing formats remain unchanged.
The cache belongs to the current round and introduces no additional historical
vote database.

The acceptance uses genuine ML-DSA keys and an authenticated TCP/Noise connection.
A peer deliberately discards the first valid vote for a real one-wei transfer,
then requests the pending block. The response must reuse the original signature;
only both distinct validators' signatures may finalize the block. Wrong-height
and mismatched-round probes must not elicit a vote. With RocksDB enabled, the
same test closes and reopens both stores and verifies their quorum certificates,
receipts, balance, and sender nonce:

```sh
cargo test --locked -p shell-node --features rocksdb \
  replays_cached_vote_after_lost_attestation -- --nocapture
```

This bounded loss experiment does not establish the cause of every native fork
timeout or prove wide-area liveness for arbitrary loss patterns and topologies.
The protocol's partial-synchrony and quorum assumptions still apply; see
[whitepaper sections 7.1 and 7.2](https://raw.githubusercontent.com/ShellDAO/white-paper/main/shell-chain-white-paper.pdf).
