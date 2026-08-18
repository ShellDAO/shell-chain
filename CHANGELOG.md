# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Performance

- Count serialized mempool transaction bytes without allocating and discarding
  a full JSON buffer during every admission attempt.
- Reuse validated reorganization blocks during commit preparation instead of
  loading every old and replacement block from storage twice.
- Avoid cloning every fork-choice score while recalculating the canonical head.

### Fixed

- Reject unknown `newPendingTransactions` subscription option fields instead
  of silently treating misspelled requests as hash-only subscriptions.
- Remove the redundant wall-clock batch-verification timing comparison from
  the unit suite; performance coverage remains in the Criterion benchmark.
- Reject account-trie records with trailing RLP bytes instead of accepting
  non-canonical persisted state.
- Count malformed direct-message streams as peer violations so repeatedly
  oversized payloads reach the configured temporary-ban threshold.
- Make oversized transaction-gossip rejection coverage synchronize on a valid
  peer message instead of passing only after a timeout.
- Reject stored RLP values and witness bundles with trailing bytes instead of
  silently accepting non-canonical records.
- Reject a release tag push atomically when canonical `main` advances after
  release lineage validation.
- Commit canonical STARK settlement artifacts atomically with produced and
  imported blocks so an artifact write failure cannot publish a partial block.
- Bound concurrent direct-message streams per peer connection by their
  aggregate payload budget so large requests cannot reserve memory using the
  count limit alone.
- Reject snapshot imports into non-empty chain stores so older snapshots cannot
  rewind canonical progress or merge stale destination records into the import.
- Commit preferred-fork STARK proof artifacts atomically with the canonical
  reorganization so an artifact write failure cannot publish a partial fork.
- Reject incomplete canonical log-query ranges instead of silently returning
  partial results when a block below the current head is unavailable.
- Return errors for invalid PQ-HD recovery phrases and mnemonic generation
  failures instead of terminating the wallet command.
- Delete rejected STARK proof-range artifacts atomically so a storage failure
  cannot leave a partially removed pointer set.
- Retry historical body back-fill requests after a response timeout so a
  dropped peer message cannot stall recovery indefinitely.
- Reject snapshots whose finalized or aggregate-totals progress is ahead of
  their canonical head before writing any imported entries.
- Keep the node event loop running when post-commit reorganization event
  publication cannot load historical receipts.
- Disconnect subscriptions after three cumulative lag events so successful
  delivery between overruns cannot indefinitely mask repeated notification gaps.
- Inspect the release binary in Cargo's configured target directory so custom
  `CARGO_TARGET_DIR` builds cannot validate or publish a stale default-path artifact.
- Commit development snapshot rewinds in one storage batch so an I/O failure
  cannot partially roll back canonical indexes or chain progress.
- Commit quorum-backed fork adoption and its finalized cursor atomically so a
  follow-up storage error cannot leave canonical state ahead of finality.
- Avoid reporting removed logs from blocks that predate a polling filter while
  still reporting matching logs from a replacement chain.
- Keep epoch-boundary validator reloads on the canonical weighted path and
  avoid producer-only offline penalties that could diverge consensus state.
- Reject malformed semantic versions throughout the release helpers, including
  leading-zero core numbers and empty or leading-zero prerelease identifiers.
- Move collected wPoA quorum signatures into the commit event instead of
  cloning every post-quantum signature when a round reaches finality.
- Reject session root authorization signatures made with algorithms deprecated
  by the runtime registry while preserving algorithm-agile key rotation.
- Create persisted libp2p identity keys exclusively with private permissions,
  and reject symbolic links or oversized identity files when loading them.
- Restore or clear the durable state-trie pruning cursor during snapshot import
  and reject snapshots whose cursor is ahead of their canonical head.
- Reject startup when durable finality metadata is malformed or inconsistent
  with the canonical chain instead of restoring volatile genesis finality.
- Keep round-robin proposer selection deterministic across target pointer widths
  for block numbers above the native `usize` range.
- Reject published releases whose GitHub prerelease state disagrees with the
  stable or prerelease status encoded in the validated semantic-version tag.
- Reject authenticated STARK amendments whose declared `compressed_size` does not match the proof artifact size, preventing underreported metadata from satisfying compression and reward policy.

## [0.27.4] — 2026-08-12 — Protocol safety and operational resilience

### Breaking Changes

- Bind the sender-bound transaction identity rules into the genesis header.
  Existing databases use the legacy identity rules and cannot be resumed by
  this release.

### Migration Guide

- Alpha testnet operators must stop the node, back up any required state, run
  `shell-node --datadir <path> removedb --force`, and initialize the chain from
  the coordinated genesis configuration before restarting. The upgraded node
  rejects legacy databases with a clear migration error.

### Changed

- Add a post-tag release check that verifies the canonical annotated tag and
  confirms the corresponding GitHub release is publicly published.
- Avoid allocating the active-validator view during weighted proposer selection
  and active-count checks.
- Revalidate canonical `main` and the exact annotated tag source after release
  confirmation, rejecting a push when either changed during the prompt.
- Make sparse parallel-execution wave planning linear in the current wave size
  by checking conflict-set disjointness against indexed wave membership.
- Make weighted proposer selection linear in the validator count and allocation-free.
- Account for the outer envelope and session-verification intrinsic gas in AA
  receipts and fee settlement, without treating the unused outer destination
  as a contract-creation request.
- Start STARK proof generation only after node readiness, and bound both the
  proof handoff queue and the number of amendments awaiting canonical
  settlement.
- Expose pending STARK settlements and rate-limited amendments as Prometheus
  metrics for prover admission monitoring.
- Require a production binary build before creating a release tag.
- Avoid allocating account-trie keys on world-state cache misses and writes.
- Run advanced CodeQL analysis for fork-based pull requests so every proposed
  head receives the required GitHub Actions, Python, and Rust security checks.
- Index pending sender and paymaster balance reservations so transaction
  admission no longer scans the full mempool.
- Commit replayed state, receipts, canonical indexes, and the replacement head
  in one atomic storage transition during branch adoption.
- Deterministically replay and atomically adopt quorum-preferred forks while
  keeping candidate execution isolated until every commitment is verified.
- Back off repeated preferred-fork adoption attempts up to 30 seconds, while
  retrying immediately when fork choice selects a different head.
- Reconcile the mempool after fork adoption by removing newly canonical
  transactions and reinserting valid reverted transactions in nonce order.
- Remove terminally invalid preferred-fork subtrees from fork choice so
  production can resume, while retaining backoff for transient failures.
- Reconstruct signature-algorithm policy from the common ancestor state before
  validating a preferred branch, with rollback when adoption fails.
- Journal canonical public-key and guardian-recovery metadata changes so fork
  replay restores the common-ancestor view before validating either branch.

### Fixed

- Bound the mDNS explicit-peer set to the configured peer limit and reclaim
  capacity when discovered peers expire.
- Commit state-trie node deletion and its durable pruning cursor atomically.
- Validate canonical suffix continuity before startup recovery rewinds to the
  durable finalized checkpoint.
- Reject `eth_getFilterLogs` results when the filter is uninstalled while the
  query is in progress.
- Evaluate custom-account, paymaster, and session authorization against the
  exact candidate block header during block production and import.
- Clear block-sync request state when sending the next peer-targeted batch
  fails, instead of waiting for a response to a request that was never sent.
- Upgrade `lru` to 0.18.2 to resolve RUSTSEC-2026-0253.
- Bind canonical signed-transaction identifiers to the authenticated sender so
  distinct accounts with identical transaction payloads cannot collide in the
  mempool, receipt, or transaction indexes while authentication witnesses
  remain excluded from the identifier.
- Revalidate imported transactions against prior in-block state changes so key
  rotations and account or paymaster policy updates take effect immediately.
- Propagate authority-registry and equivocation lookup storage failures during
  block import instead of misclassifying them as unknown proposers or missing
  equivocation evidence.
- Prevent custom-validator V2 policy reverts from retrying through the reduced
  legacy V1 authorization interface.
- Bind snapshot checksums to framed key and value records and require the
  checksum in snapshot format version 2.
- Keep historical STARK frontier tasks ordered ahead of live tip tasks and
  retain sparse frontier ranges instead of skipping them into proofs that
  canonical settlement must reject.
- Reserve STARK source ranges while proofs are in flight so periodic frontier
  seeding cannot generate duplicate amendments during proof handoff.
- Revalidate persisted STARK amendments before startup recovery, discard
  malformed or unauthenticated artifacts, and regenerate their proof tasks
  instead of repeatedly blocking the settlement window.
- Accept a rotated wPoA proposer during historical block sync only with a
  verified commit certificate and after the deterministic view-change timeout,
  so restarted validators can synchronize safely after a valid view change.
- Apply backpressure to STARK proof generation and authenticated amendment
  gossip so an unsettled historical frontier cannot starve block propagation.
- Bind block-sync responses to the requested starting height before importing
  any peer-supplied blocks.
- Prune address-metadata undo journals once their blocks are finalized, while
  retaining every journal that a valid reorganization can still require.
- Reject side-fork blocks with malformed or invalid STARK aggregate proofs
  before persisting them or registering them with fork choice.
- Keep idle `syncing` subscriptions active until the client unsubscribes or
  disconnects instead of expiring healthy WebSocket sessions.
- Require owners to cancel an active guardian recovery before replacing its
  guardian configuration, preventing votes under the old configuration from
  remaining executable.
- Preserve AA inner-call balance effects during sponsored-gas settlement so
  self-transfers and value received by paymasters are not discarded.
- Keep an mDNS peer explicit in GossipSub until all of its discovered addresses
  have expired.
- Reject checkpoint snapshots with a missing or mismatched canonical head body
  before importing any snapshot records.
- Start finality-bounded log filters at their resolved upper bound so blocks
  already above that bound are delivered when finality later advances.
- Let higher-priority transactions evict enough lower-priority nonce chains to
  satisfy the aggregate mempool byte limit as well as the transaction-count
  limit.
- Reject release cuts when the exact tag already exists on the canonical remote,
  before creating a conflicting local tag.
- Stop retaining expired mDNS discoveries as dialable peer addresses.
- Reject headless genesis snapshots before they can replace stored chain data
  or clear the published chain head.
- Reject commit certificates for missing, height-mismatched, or noncanonical
  blocks before advancing finality.
- Resolve log-filter `fromBlock` tags when the filter is created so later polls
  cannot skip matching blocks.
- Reject sender-paid transactions whose maximum gas cost plus transferred value
  exceeds the U256 balance range.
- Reject algorithm-activation proposals when the canonical head cannot be read,
  instead of validating their timelock against a fallback genesis height.
- Require successful exact-commit CodeQL analyses for GitHub Actions, Python,
  and Rust before creating a release tag.
- Reject aggregate pending balance reservations that exceed the U256 balance
  range.
- Reject blob transactions whose versioned hashes do not use the EIP-4844 KZG
  version byte.
- Return an internal error from `eth_getLogs` when a matching canonical block
  has a non-zero log bloom but its receipts are unavailable.
- Recover the persisted finalized hash from canonical indexes after restart so
  body-pruned finalized blocks do not reset the in-memory checkpoint hash.
- Reject snapshot exports whose chain identity does not match the persisted
  chain configuration.
- Reject historical body responses that do not start at the requested block.
- Respect custom-validator and session-key signature policies during block
  import and side-fork validation.

## [0.27.3] — 2026-07-26 — Blob fee arithmetic hardening

### Fixed

- Saturate blob base fees at the supported numeric maximum while preserving
  monotonic pricing at high excess gas.

## [0.27.2] — 2026-07-26 — Finality safety and correctness hardening

### Fixed

- Stop fixed-range log filters at their resolved `toBlock` instead of advancing
  their polling cursors through unrelated later blocks.
- Count the block transaction limit against included transactions so skipped
  candidates cannot suppress later eligible transactions.
- Index transaction receipts by included block order when earlier mempool
  candidates are skipped during block assembly.
- Reject duplicate validator identities in genesis and persisted validator
  registries before they can receive repeated consensus weight.
- Reject release commits whose workspace manifests and `Cargo.lock` disagree,
  before a tag can be created or hosted checks can pass.
- Avoid cloning every signed transaction during block import when validation
  can borrow the original block transaction unchanged.
- Reject session-key transactions at their exclusive expiry height by checking
  the next candidate block rather than the stored parent height.
- Enforced paymaster authorization after every sender-account validation path.
- Enforce the 50 MiB protocol-wide raw P2P message ceiling even when an
  embedding application supplies a larger network configuration value.
- Validate that an imported snapshot's non-empty head state root is present and
  readable before publishing its chain progress metadata.
- Finalize only canonical blocks and persist the finalized cursor before
  advancing volatile finality state, while retaining quorum attestations for
  retry after transient storage failures.
- Make polling log and block filters reorg-aware, returning removed logs and
  canonical replacement results before advancing their cursors.
- Keep pending-balance reservation checks linear when pool-capacity eviction
  removes a sender's nonce descendants.
- Reject side-fork blocks with empty, invalid, unresolved, or sender-mismatched
  transaction signatures before storage or fork-choice admission.
- Anchor Unix backup restore traversal to no-follow directory handles and
  nonblocking, no-follow file handles so source replacement cannot redirect or
  stall reads.
- Open sensitive CLI input files with no-follow semantics on Unix, closing the
  final-component symlink race before validating the opened file identity.
- Remap local build paths out of precompiled release binaries, omit
  nondeterministic macOS linker UUIDs, and refresh embedded revision metadata
  after branch advances.
- Keep the published security support line, version badge, container example,
  and fuzz manifest aligned with the workspace release version.
- Size the world-state account cache from decoded entry memory and honor a
  zero-MiB budget with the minimum LRU capacity instead of the default cache.
- Resolve custom-validator and contract-paymaster state reads against full
  32-byte Shell addresses instead of lossy 20-byte EVM aliases.
- Keep the reported libp2p peer count aligned with admitted unique peers so connections rejected by peer limits cannot transiently inflate RPC and sync readiness metrics.
- Keep canonical block mappings until both body and witness pruning have
  processed them, so delayed STARK settlements cannot strand retained data.
- Release the consensus read lock before RPC validator stake lookups and reuse
  one world-state read guard for the full validator snapshot.
- Bound proof-amendment gossip envelopes to the signed payload hash and source
  range end before applying witness-replacement retention behavior.
- Retain expired grace-window witness deletions for retry when storage returns
  a transient error instead of silently abandoning cleanup.
- Audit the patched libp2p-yamux lockfile in CI and release preflight, and
  refresh its vulnerable `bytes` dependency.
- Remove queued nonce descendants when block production permanently rejects a
  transaction, preserving contiguous sender queues and byte accounting.
- Make the JSON-RPC response-body limit explicit and configurable across HTTP,
  WebSocket, and combined listeners.
- Require finality votes and commit certificates to carry strictly more than
  two thirds of active validator weight, reject zero-total-weight finality and
  view-change quorums, preserve the nonzero view-change liveness threshold, and
  atomically persist wPoA certificates and finalized cursors before advancing
  volatile finality.

## [0.27.1] — 2026-07-14 — Consensus and RPC correctness fixes

### Fixed

- Bound finality vote aggregation and advancement to the complete signed
  attestation target metadata.
- Kept RPC filter cursors monotonic while preserving expiration behavior.
- Skipped underpriced mempool entries when assembling block candidates so
  later eligible transactions remain available for inclusion.

## [0.27.0] — 2026-07-12 — Security and state-integrity hardening

### Changed

- New SPHINCS+ fallback keys and signatures now use the maintained FIPS 205
  SLH-DSA-SHA2-256f implementation while retaining the documented wire format.
- TLS PEM parsing now uses the rustls native PKI types, removing the redundant
  parser dependency.
- Network message routing now requires explicit topics and applies bounded
  decoding, sync-response, ban-duration, and bandwidth accounting rules.

### Fixed

- Rejected AA bundles whose inner-call value sum overflows `U256` before
  comparing against the outer transaction value.
- Rejected AA bundles that set the sender as their own paymaster, preserving
  the self-sponsored gas and value balance invariant.
- Deferred first-use pubkey registration until transaction validation passes
  nonce and balance checks.
- Bound AA session-key root authorizations to the declared session signature
  algorithm.
- Hardened snapshot import and restore validation, canonical index updates,
  world-state accounting, checkpoint handling, and pruning counters against
  malformed metadata, partial updates, and arithmetic boundaries.
- Bounded RPC filters, subscriptions, logs, fee-history percentiles, calldata,
  access lists, batch inner calls, and reflected error input before expensive
  processing.
- Corrected pending nonce, receipt, gas-usage, finality, terminal-height,
  mempool sequence, and transaction validation behavior at boundary values.
- Preserved consensus liveness and deterministic proposer behavior across
  terminal heights, stale attestations, validator weights, rate limiting, and
  STARK backlog boundaries.
- Required canonical paymaster boolean encoding and guarded staking balance,
  total-supply, minimum-stake, and weight calculations.

## [0.26.0] — 2026-07-07 — Stake-derived wPoA genesis economics

### Added

- Added staking-enabled wPoA genesis economics: `initial_supply`,
  `stake_unit`, `min_validator_stake`, `max_validator_weight`, and
  per-validator locked `stakes`.
- Validator weights can now be derived from staked SHELL at genesis and stored
  in the validator registry alongside total supply and total staked counters.
- Added system-contract calldata and RPC helpers for stake-driven validator
  governance.

### Changed

- Updated testnet/devnet genesis examples to use a non-zero 2026 genesis
  timestamp and documented the initial supply invariant.

## [0.25.2] — 2026-07-07 — Runtime hardening and RPC bounds

### Fixed

- Hardened JSON-RPC validation for filters, trace options, raw byte fields,
  log topics, fee history, paymaster simulation, and governance gas estimation
  so malformed requests fail before expensive work.
- Bounded block/body sync imports and response handling to avoid unbounded
  memory use from peers or control messages.
- Preserved pending balance reservations for standard, sponsored, and AA
  transactions, reducing nonce and balance races in the mempool.
- Validated reorg chain segments, finalized fork ancestors, pending block
  candidates, and block gas accounting during node operation.
- Improved witness, finality-tag, pruning, STARK proof amendment, and
  storage-profile behavior under edge-case queries.

## [0.25.1] — 2026-06-29 — RPC v2 correctness fixes

### Fixed

- Removed stale canonical transaction/address index entries during reorg and
  dev snapshot revert paths, so RPC v2 address history no longer returns
  orphaned-branch transactions.
- Re-indexed side-fork blocks when they become canonical during reorg.
- Fixed `shell_getBlocksRange` pagination so `nextStart` is only returned when
  a real next canonical block exists.
- Updated audited Rust dependency lock entries for `anyhow` and
  `bitcoin_hashes`.

## [0.25.0] — 2026-06-29 — RPC v2 and PQVM contract readiness

### Added

- Efficient Shell RPC v2 endpoints for explorers, wallets, dApps, and node
  operators: `shell_rpcCapabilities`, `shell_getChainSnapshot`,
  `shell_getBlocksRange`, `shell_getAddressSummary`,
  `shell_getTransactionsByAddressV2`, `shell_getTransactionSummary`, and
  `shell_getValidatorSnapshot`.
- Lightweight address-history storage index with cursor pagination support,
  avoiding full-chain scan-and-sort behavior for high-traffic address queries.
- PQVM native address opcode support for Shell smart contract execution.
- Testnet resource guardrails and systemd operator examples for safer
  deployments.

### Changed

- RPC list-style APIs now enforce bounded ranges and summary-first responses
  for the new v2 surface, reducing explorer fan-out and response size.
- Documentation and runbooks were refreshed so quickstart, CLI automation,
  JSON-RPC, keystore, node CLI, observability, and testnet operator tutorials
  match the current node behavior.

### Fixed

- Block production now preserves isolated world-state behavior and rolls back
  correctly on production failures.
- New-account nonce handling now uses the default nonce path instead of
  requiring pre-existing account state.
- Chain stats count visible system transactions consistently.
- PQVM contract tests derive nonces from state instead of relying on hard-coded
  values.

## [0.24.3] — 2026-06-13 — CI parity hardening

### Fixed

- **Event-loop unit tests under socket-restricted sandboxes**: `Node::run` now
  supports disabling JSON-RPC startup through `NodeConfig::rpc_enabled` while
  preserving RPC startup by default for normal node operation. Event-loop tests
  that do not exercise RPC disable it explicitly, removing sandbox-only
  `Operation not permitted` bind failures from `make ci`.

## [0.24.2] — 2026-06-07 — Consensus liveness hardening

### Fixed

- **Slashed-validator slot deadlock in PoA proposer selection**: proposer slot
  selection now uses slash-adjusted effective validator weights. Validators
  fully slashed to effective weight `0` are excluded from slot assignment, so
  remaining active validators can continue producing valid blocks.

## [0.23.0] — 2026-05-22 — Round 3 completion

### Added

- **Algorithm registry governance runtime**: `AlgorithmRegistry` is now mutable at runtime, validator governance can propose, activate, and deprecate signature algorithms via native system-contract calls, and RPC exposes the live registry through `shell_getAlgorithmRegistry`.
- **wPoA view-change rotation**: signed `WPoaViewChange` messages now advance the proposer view after timeout using the same weighted quorum model as finality.
- **STARK challenge lifecycle tracking**: proof challenges are recorded as `Open`, transition to `Resolved` on a valid response, and automatically become `Slashed` after the `T_c = 7200` block timeout.
- **State-trie pruning path**: `prune_state_trie()` now prunes unreachable trie snapshots for `StorageProfile::Light`, complementing witness/body pruning.

### Changed

- **Economic slashing is weight-aware**: PoA and wPoA now apply `slash_weight_bps` reductions to a validator's effective weight, flooring at zero across repeated offences.

### Fixed

- **Bandwidth/liveness cleanup**: Round 3 network hardening reduces stale proof/challenge traffic and aligns docs with the current R3 implementation.

## [0.22.2] — 2026-05-12

### Fixed

- **STARK drain-reseed infinite loop** (`stark_drain_frontier` atomic): the
  prover could enter a permanent cycle where sparse blocks before a settled gap
  were drained every 60 s and immediately re-seeded because `scan_start` never
  advanced past the gap. A shared `Arc<AtomicU64>` is now updated to
  `gap_at_block` after every `drain_front()` call; the seeder clamps
  `scan_start` to `max(contiguous_pending_end − 16, drain_frontier)`, breaking
  the loop permanently. Verified on testnet: `frontier_lag` dropped from
  4 807 to **1** within five minutes of deployment.
- **Reseed anchored at contiguous settled frontier** (Fix B): `scan_start` is
  now derived from `contiguous_pending_end` — the highest block reachable
  without gaps through settled + gapless-pending amendments — instead of raw
  `pending_max_block`. This prevents re-seeding already-proven ranges when
  pending amendments arrive out-of-order.
- **Pre-gap sparse drain** (Fix A): when `pop_contiguous_with_min_entries`
  returns `None` due to a gap and the contiguous prefix has stalled for
  `stall_timeout`, the prover now drains and discards the stuck prefix and
  signals `needs_reseed`, allowing the backlog to advance past the gap.
- **Amendment artifact cleanup on ordering failure**: local proof amendments
  that fail the ordering-validation check are now deleted from the amendment
  store instead of being left as orphaned artifacts that could trigger spurious
  reseeds on restart.
- **Witness pruner safety**: witness data is no longer pruned for blocks that
  do not yet have a settled STARK proof, preventing data-loss races during
  catch-up.

## [0.22.1] — 2026-05-10

### Changed

- Version bump for the next coordinated ShellDAO release cut.

## [0.22.0] — 2026-05-06 — Stability, STARK hardening, and ops maturity

### Added

- **Durable STARK settled-source index** (`ss/` key prefix): settled `(layer,
  source_hash)` pairs are now written to persistent storage on every settlement.
  Node restart loads from the index in O(prefix-scan) instead of scanning all
  blocks; first-run backfills the index automatically from chain history.
- **O(3) `compression_layer_for_source` lookup**: replaced O(n-settled) linear
  scan with a constant-cost check across layers 1–3, eliminating the
  performance cliff as the settled set grows.
- **Proof input decode in RPC**: `system_tx_to_rpc` now decodes `StarkReward`
  transaction payloads into a structured `decodedInput` JSON field (block
  range, layer, entry count, compression sizes, settlement tx hash).
- **Settlement liveness metrics**: added Prometheus counters/gauges
  `shell_stark_settlements_accepted_total`, `shell_stark_settlements_rejected_total`,
  and `shell_stark_frontier_lag`.
- **`SettledSourceIndex`** re-exported from `shell-storage` for use by
  downstream tooling and tests.
- **Restart-recovery tests**: `stark_settled_index_survives_simulated_restart`
  and `import_invalid_stark_settlement_does_not_poison_settled_index`.

### Changed

- Settlement validation now increments `stark_settlements_rejected` on any
  ordering/layer/frontier rejection, enabling ops monitoring of invalid proof
  traffic.
- `rebuild_settled_stark_sources_from_chain()` uses the persistent index as a
  fast path; falls back to chain scan only when index is absent (upgrade path).

## [0.21.1] — 2026-05-06 — STARK settlement hardening patch

### Fixed

- Harden STARK settlement/reward handling so proof payloads are carried by
  canonical `StarkReward` system transactions and imported blocks materialize
  proof pointers consistently.
- Preserve legacy block RLP compatibility for pre-`system_transactions` blocks
  with non-empty proposer seals.
- Prevent STARK prover backlog stalls on long low-entry L1 ranges at the
  configured max-source window.
- Align node tests with current system reward receipts, continuous STARK
  frontier ranges, and 2s testnet block cadence.

## [0.21.0] — 2026-05-02 — F-PQ1-ONLY + F-FORK-FINALITY

### Breaking Changes

- **`0x` hex address format completely removed** (F-PQ1-ONLY): All user-facing addresses
  (RPC responses, CLI output, genesis files, keystore `address` field, explorer) now use
  canonical `pq1...` bech32m format exclusively. Legacy `0x` addresses are no longer
  accepted by any input path. This affects:
  - `shell-node` CLI (`key generate`, `key inspect`, `tx send`, `run`, `genesis add-alloc`)
  - JSON-RPC: `eth_getBalance`, `eth_getTransactionCount`, `shell_getPqPubkey`, etc.
  - `shell-sdk`: `getAddress()` returns `pq1...` (was `getHexAddress()`, now removed)
  - Genesis files: `alloc` map keys must be `pq1...` addresses
  - Keystores: `address` field uses `pq1...` (was `0x`-hex)

### Added

- **BFT finality and fork protection** (F-FORK-FINALITY phase 1):
  - wPoA quorum votes now advance `FinalityState` and persist the latest finalized
    block number.
  - Commit certificates are stored as block-hash sidecars containing validator
    `PQSignature`s, preserving block hash compatibility.
  - Block import, vote handling, and production reject conflicts with already
    finalized heights.
  - Sync responses carry commit-certificate sidecars so peers can fast-finalize
    after verifying signer membership, PQ signatures, and weighted quorum.
  - RPC/Explorer/metrics surfaces added: `shell_getFinalityInfo`,
    `shell_finalityProof`, finalized block tag support, block finality badges,
    `shell_last_finalized_number`, and `shell_finality_lag_blocks`.

- **STARK aggregate proof infrastructure** (STK.1–STK.5):
  - `--enable-stark-aggregation` defaults to **`false`** so ordinary validators
    do not run local proof work unless explicitly configured as prover-capable.
  - `RpcHandler` gains a `proof_amendment_store` field; `block_to_rpc` fallback queries
    the `ProofAmendmentStore` when `sig_aggregate_proof` is `None` in the block header.
  - New RPC method `shell_getProofAmendment(blockHash)` — returns the STARK proof
    amendment for a block if one has been generated asynchronously.
  - Metric `stark_amendments_queried_total` incremented when amendment is returned.
  - Explorer block detail page shows `sigAggregateProof` badge and STARK proof section.

- **Faucet service rewritten with PQ signing** (`agents/faucet`):
  - Replaced `ethers` + ECDSA private key with `shell-sdk` keystore + PQ signing.
  - Faucet authenticates via `decryptKeystore` + `ShellSigner`.
  - New `/drip` endpoint (was `/faucet`). Accepts `pq1...` address only.
  - Local nonce management prevents concurrent-request corruption.

- **New docs**:
  - `docs/stark-aggregation.md` — STARK aggregate proof architecture and RPC reference.
  - `docs/genesis-format.md` — Genesis JSON schema, field reference, and examples.

### Fixed

- **CLI tests**: `env_password_empty_falls_through_to_error_on_tty` marked `#[ignore]` to
  prevent blocking on real TTY (and deadlocking `ENV_LOCK` mutex in test suite).
- **Keystore `encrypt_sphincs`**: `address` field now uses `address.to_string()` (pq1 format)
  instead of legacy `format!("0x{}", hex::encode(...))`.
- **CLI `parse_valid_address`**: Test now asserts that `0x` hex addresses are **rejected**.
- **Wallet test fixture**: Updated from `0x000...0001` to canonical pq1 address.

### Migration Guide (F-PQ1-ONLY)

1. **All `0x` addresses in genesis files** must be updated to `pq1...` format.
   Use `shell-node key inspect <keystore.json>` to get the pq1 address.
2. **SDK users**: Replace `signer.getHexAddress()` with `signer.getAddress()`.
   Replace `0x...` address strings in all RPC calls with `pq1...`.
3. **Keystores**: Re-generate or re-encrypt; `address` field is now stored as `pq1...`.
   Old keystores with `0x` address field are still **readable** (backwards compat).
4. **Faucet**: Replace `FAUCET_PRIVATE_KEY` with `FAUCET_KEYSTORE_FILE` + `FAUCET_KEYSTORE_PASSWORD`.

---

### F-TESTNET-FIXES

### Added

- **ML-DSA-65 (FIPS 204) as independent first-class algorithm** (`crates/crypto/mldsa.rs`):
  ML-DSA-65 is now a genuine FIPS 204 implementation using the `fips204` crate — not a
  Dilithium3 alias. `SignatureType::MlDsa65` (algo_id=1) is enabled in `ALLOWED_ALGORITHMS`.
  `MlDsaSigner` and `MlDsaVerifier` implement the `Signer`/`Verifier` traits alongside the
  existing `DilithiumSigner`. Cross-language signing verified: Rust-generated ML-DSA-65
  signatures verified by `shell-sdk`, and vice-versa. (**SIG.1–SIG.9**)

- **Keystore v1 sk-only unified format** (`crates/keystore`): Both Rust CLI and TypeScript SDK
  now store only the secret key in the encrypted ciphertext (`sk-only`). The `public_key` field
  is stored in plaintext alongside. `shell-sdk decryptKeystore()` can now directly decrypt
  keystores produced by `shell-node key generate` without any workaround. `key_type` supports
  `"dilithium3"` and `"mldsa65"`. (**KS.1–KS.4**)

- **CLI non-interactive password support** (`crates/cli/src/password.rs`):
  Three new password resolution methods for CI/automation:
  - `--password-file <path>`: read password from a file
  - `--password-stdin`: read password from stdin (one line)
  - `SHELL_KEYSTORE_PASSWORD` env var (requires `--allow-env-password` flag)
  All key subcommands (`key generate`, `key inspect`, `key migrate`) and `run` use the new
  `resolve_password()` resolver. (**CLI.1–CLI.3**)

- **`shell-node key migrate` subcommand** (`crates/cli/src/commands/key.rs`): Migrates an
  existing keystore to a different format (e.g. old sk‖pk format → sk-only v1). Outputs
  to a new file path. (**KS.7**)

- **`shell-node genesis add-alloc` subcommand** (`crates/cli/src/commands/genesis.rs`): Adds an
  address/balance entry to a genesis JSON file's `alloc` section in-place. Simplifies test
  account provisioning. (**GEN.2**)

- **`agents/genesis-builder/`**: Node.js agent script that scans a keystore directory and
  generates an `alloc` section for a genesis file. Supports `--dry-run`, `--balance`,
  `--chain-id`. (**GEN.1**)

- **Testnet test-accounts template** (`infra/testnet/test-accounts/`): Documentation template
  describing keystore format, genesis alloc entry, and address format for the 10 testnet
  test accounts. (**GEN.3**)

- **Testnet archive manifest** (`infra/testnet/archive/MANIFEST.md`): Documents the genesis-0
  testnet reset (2026-04-28), backup location on server, and post-reset state. (**RST.8**)

- **CLI automation guide** (`docs/cli-automation.md`): Comprehensive guide for non-interactive
  password usage in CI, Docker, and systemd environments. (**CLI.4**)

- **Node CLI reference** (`docs/node-cli.md`): Full v0.21.0 flag reference for all `shell-node`
  subcommands. (**CLI.5**)

- **Keystore format spec** (`docs/keystore-format.md`): Canonical v1 keystore schema
  specification. Documents KDF (argon2id), cipher (XChaCha20-Poly1305), and SDK compat. (**KS.5**)

- **CONSTITUTION v1.5** (`projects/shell-chain/CONSTITUTION.md`): ML-DSA-65 promoted to
  production in §13.1 (independent FIPS 204 algo, not Dilithium3 alias). Keystore v1 sk-only
  and CLI non-interactive password also added to §13.1. §2.7 PQ crypto table updated.

### Fixed

- **`address` field now has `0x` prefix** in keystore JSON (`crates/keystore/src/crypto.rs`):
  Previously written as bare hex `"ea119c03..."`, now `"0xea119c03..."`. Old keystores
  (without prefix) are still readable via `trim_start_matches("0x")`. (**KS.6**)

- **`SIG_IDS` bugfix** (`shell-sdk`): `SIGNATURE_TYPE_IDS.MlDsa65` now correctly maps to `1`
  (not `0`). This fixes address derivation for ML-DSA-65 keys in the SDK.

- **block_time override no longer logs a warning** (`crates/cli/src/commands/run.rs`): Explicit
  `--block-time` override is logged at `info` level rather than `eprintln!` error/warning,
  since the override is intentional. (**CLI.6**)

- **Explorer address page missing transactions** (`shell-explorer`): Fixed batch RPC handler
  to correctly aggregate transaction history per address. (commit `5e35652`) (**F-EXPLORER-FIX**)

### Breaking Changes

- **ML-DSA-65 `algo_id` changed from `0` to `1`**: If you have existing ML-DSA-65 keystores
  signed with the old Dilithium3-alias behaviour, use `shell-node key migrate` or re-generate.
  All **Dilithium3** keystores (`algo_id=0`, `key_type="dilithium3"`) are unaffected.
- **Keystore `ciphertext` format changed**: SDK `encryptKeystore()` now stores sk-only (not
  sk‖pk). Old SDK-generated keystores with sk‖pk format must be re-encrypted with the new SDK.

### Migration Guide

1. **ML-DSA-65 keys**: Re-generate with `shell-node key generate --algorithm mldsa65`.
   Old keys generated before F-TESTNET-FIXES are Dilithium3 with an incorrect `key_type`
   field — they will not verify correctly as ML-DSA-65.
2. **SDK keystores (sk‖pk)**: Re-encrypt with updated `shell-sdk encryptKeystore()` (v0.6.0+).
   Or use `shell-node key migrate --input old.json --output new.json`.
3. **Testnet**: The testnet was reset to genesis-0 on 2026-04-28. All old test accounts have
   been replaced. See `infra/testnet/test-accounts/` and `infra/testnet/archive/MANIFEST.md`.

## [0.20.0] — 2026-04-27

### Added

- **wPoA consensus engine activation (W.1–W.7)** (`crates/consensus`, `crates/node`,
  `crates/cli`): Weighted Proof of Authority consensus is now a first-class production
  path. `NodeConfig.consensus: ConsensusEngineConfig` selects `Poa` or `WPoa` at startup.
  The `ConsensusEngine` trait is fully dyn-safe with `sign_block`, `verify_seal`,
  `validator_weights`, and `poa_config` methods. A complete `WPoaRound` state machine
  (`propose → vote → commit + view-change`) implements weighted quorum `⌈2/3 × total_weight⌉`.
  CLI flag `--consensus-engine poa|wpoa`; auto-detection from genesis `engine` field.
  8 wPoA e2e tests covering 3-validator quorum, view-change, network split.

- **`shell_consensusInfo` RPC (W.6)** (`crates/rpc`): New method returns current engine
  type, epoch length, and the live validator set with weights.

- **wPoA testnet genesis (T.1)**: Added `WPoA` variant to `ConsensusConfig` in the genesis
  crate (`crates/genesis`). Genesis files with `"engine": "wpoa"` are now parsed and
  initialized correctly. Helper methods (`authorities()`, `block_time_secs()`, etc.) replace
  exhaustive match arms across the codebase. New example: `examples/genesis-testnet-wpoa.json`
  (chain_id=10, 3 validators, weights=[2,1,1]).

- **Peer scoring bridged to network ban list (PS.2)** (`crates/node`):
  `Node` now holds a `peer_ban_list: Mutex<PeerBanList>` field. After every wPoA vote,
  `flush_scorer_bans()` propagates peers whose score has fallen below the disconnect threshold
  into the network-layer `PeerBanList` (3 violations → 5-minute ban). The bridge converts
  `ScoringPeerId → PeerId` between the consensus and network layers.

- **wPoA testnet deploy manifests (T.2)** (`infra/testnet/`): New directory with
  `docker-compose.yml` (3-validator cluster, chain_id=10), `prometheus.yml` scrape config,
  and operator `README.md`.

- **Faucet service (T.3)** (`agents/faucet/`): New standalone Node.js/TypeScript HTTP service
  using Fastify + ethers.js. `POST /faucet` drips 1 SHELL per IP per 24h; `GET /health`
  returns current block number. Rate limiting via `@fastify/rate-limit`.

- **Testnet documentation (T.4)** (`shell-site`): New `content/docs/testnet.md` covering
  network parameters (chain_id=10), MetaMask setup, faucet usage, smart contract deployment,
  and read-only node operation.

- **Explorer network update (T.5)** (`shell-explorer`): `networks.ts` default chain ID updated
  from `1337` to `10`; network name updated to "Shell Testnet" for wPoA testnet.

- **Wallet testnet preset update (T.6)** (`shella-chrome-wallet`): `KNOWN_NETWORKS.testnet`
  chain ID updated from `12345` to `10` to match wPoA genesis.

- **CONSTITUTION v1.4** (`projects/shell-chain/CONSTITUTION.md`): wPoA engine and
  consensus PeerScoring promoted from lib-only to production (PS.3). §13.2 cleaned up;
  §13.4 updated; §13.5 fully rewritten to document the two-layer peer scoring bridge.

- **RPC doc autogen (R.1–R.3)** (`tools/rpc-docgen`): `cargo run -p rpc-docgen` generates
  `docs/rpc-reference.md` (75 methods, 7 namespaces). CI step `rpc-docgen --check` prevents
  drift. Version bumped to `0.20.0-dev`.

## [0.19.0] — 2026-04-26

### Added

- **I4: ProofWindowManager wired into node** (`crates/node`): `Node` now holds a
  `ProofWindowManager` instance (default `WindowConfig`). `advance()` is called on
  every block import; `gc()` runs every 100 blocks. This moves I4 from `lib-only`
  to production and enables prover claim/squatting tracking in the wPoA era.
  See `crates/consensus/src/window.rs` and CONSTITUTION §13.2.

- **AA Phase 2 wire format** (`crates/core`): `AaBundle` extended with
  `paymaster_context: Option<Bytes>` (contract paymaster) and
  `session_auth: Option<SessionAuth>` (session key delegation). `SessionAuth`
  carries `session_pubkey`, `session_algo`, optional `target`, `value_cap`,
  `expiry_block`, `root_signature`, and `session_signature`. RLP encodes as a
  5-field list. Breaking change vs v0.18.x wire format. See `docs/AA_PHASE2_SPEC.md`.

- **AA Phase 2 contract paymaster** (`crates/pqvm`): `validatePaymasterOp` ABI call
  dispatched when `paymaster_context` is present. Call runs in a world-state
  snapshot (mutations discarded). Gas cap 50k. Bool return decoded from 32-byte
  ABI word.

- **AA Phase 2 session keys** (`crates/pqvm`): Session-key-signed AA bundles now
  validated via two-step PQ verification: (1) root key authorizes the session key
  via `session_auth_hash`; (2) session key signs the tx via `sender_signing_hash`.
  Constraint checks: expiry block, value cap (Σ inner call values), optional target
  restriction. New error variants: `SessionKeyExpired`, `SessionValueCapExceeded`,
  `SessionTargetMismatch`, `SessionRootSignatureInvalid`, `SessionKeySignatureInvalid`,
  `SessionKeyDisallowedAlgorithm`.

- **AA Phase 2 guardian recovery** (`crates/pqvm`, `crates/storage`): `AccountManager`
  system contract gains 4 new entry points: `setGuardians(address[],uint8,uint64)`,
  `submitRecovery(address,bytes,uint8)`, `executeRecovery(address)`,
  `cancelRecovery(address)`. `GuardianConfig` and `RecoveryProposal` persisted in
  `ChainStore` under `gc/` and `rp/` key prefixes. Invariants: max 5 guardians,
  min 100-block timelock, k-of-n threshold, no self-guardian, no duplicate votes.
  After threshold reached, maturity block = current + timelock; anyone may execute
  after maturity. Owner may cancel before execution. See `docs/AA_PHASE2_SPEC.md §5`.

### Fixed

- **Double PQ signature verification** (`crates/pqvm`): `validate_tx()` and
  `validate_tx_for_import()` both previously called `verify_paymaster_signature()`
  after already invoking `validate_aa_tx()` which performs the same check internally.
  The redundant second call is now removed; PQ (Dilithium) sig verification is
  performed exactly once per path (~3KB sig overhead). Addresses the review
  comment on PR #26.

### Changed (operator-visible)

- **Default block-production behavior**: `--max-idle-interval` (CLI) /
  `NodeConfig.max_idle_interval_ms` now default to **`60` seconds (`60_000` ms)**
  instead of `0`. By default, a node will skip empty blocks while the mempool is
  empty and produce a heartbeat block at most every 60 s. To restore the legacy
  every-tick behavior, pass `--max-idle-interval 0`. Synchronization, light-client
  checkpointing, and timestamp monotonicity are unaffected because the heartbeat
  upper bound is bounded (Constitution Invariant H-1). See
  `crates/node/src/node/event_loop.rs:190-210` and Constitution §2.4.

## [0.18.0-patch1] — Drift Audit: snake_case RPC + Paymaster Hardening

### Fixed

- **RPC wire format (client-breaking)**: All five new v0.18.0 `shell_*` RPC methods
  returned or accepted camelCase JSON keys; SDK `types.ts` uses snake_case throughout,
  causing silent parse failures on every AA call from SDK ≥ 0.4.0 clients.
  - `shell_estimateBatch` request: `innerCalls` → `inner_calls`, `gasLimit` → `gas_limit`
  - `shell_getPaymasterPolicy` response: `hasPqPubkey` → `has_pq_pubkey`,
    `pubkeyBytes` → `pubkey_bytes`, `maxGasSponsorship` → `max_gas_sponsorship`
  - `shell_isSponsored` response: `isAaBundle` → `is_aa_bundle`,
    `innerCallCount` → `inner_call_count`; not-found path now returns all 7 fields
  - `shell_getStorageProfile` response: removed `rename_all = "camelCase"` from
    `StorageProfileInfo`; docs corrected (`proof_replacement_grace` for archive =
    `u64::MAX = 18446744073709551615`, not `0`)
- **Mempool paymaster balance check**: mempool now correctly checks the **paymaster's**
  balance for sponsored AA bundles instead of the sender's, preventing sponsored bundles
  with an insolvent paymaster from entering the pool (F-020 extension)
- **Mempool paymaster signature verification**: `validate_aa_tx` now verifies the
  paymaster signature at mempool admission, not only at block import time; forged
  paymaster authorizations are rejected early
- **`BATCH_SIGNING_HASH_DOMAIN` comment**: clarifies intentional equality with
  `AA_BUNDLE_TX_TYPE = 0x7E` (different semantic contexts, same byte value is safe)

## [0.18.0] — Native Account Abstraction Phase 1 + Operations Hardening

> Released on branch `feat/v0.18.0-dev`. Workspace version: `0.18.0-dev`.

### AA Phase 1: Batch Transactions

- **`AaBundle` wire format** (`tx_type = 0x7E`): new `AaBundle` struct carrying
  `Vec<InnerCall>` with per-call `to / value / data / gas_limit`; single PQ signature
  covers the entire batch (`batch_signing_hash` domain-separated from legacy hashes).
- **Atomic execution**: any inner call failure reverts the entire bundle; gas and nonce
  deducted once for the batch; individual receipts produced per inner call.
- **`shell_estimateBatch`**: estimates per-inner and total gas for a batch request,
  returns `total_gas / outer_intrinsic / inner_sum / intrinsic_surcharge / per_inner`.
- **`shell_sendTransaction`**: accepts AA-bundle `SignedTransaction` directly;
  mempool validates bundle structure and verifies `batch_signing_hash` signature.
- `AA_BUNDLE_TX_TYPE = 0x7E`, `MAX_INNER_CALLS = 16`,
  `AA_INNER_CALL_INTRINSIC_GAS` per extra inner call.

### AA Phase 1: Sponsored Gas (Paymaster)

- **Native paymaster** fields in `AaBundle`: `paymaster: Option<Address>` +
  `paymaster_signature: Option<Bytes>` (PQ sig over `paymaster_signing_hash`).
- **`shell_getPaymasterPolicy(address)`**: returns paymaster's registered balance,
  pubkey presence, and policy (`eoa-open` default).
- **`shell_isSponsored(txHash)`**: returns
  `{found, sponsored, is_aa_bundle, paymaster, sender, inner_call_count, location}` for
  any queried tx hash (mempool or chain).
- Paymaster fields fully optional; legacy transactions unaffected.

### OPS-1: Storage Profile

- `archive / full / light` profiles wired to CLI flag, node config, and
  `shell_getStorageProfile` RPC.
- Node startup validates profile-disk consistency; safe runtime-switch path
  (archive↔full only).
- `docs/storage-profiles.md` with profile comparison table and migration guide.

### OPS-2: Witness Endpoint Hardening

- `shell_getWitness` returns full Merkle proof + state root + block context on
  archive/full nodes (no longer 501).
- `shell_verifyWitnessRoot`: new RPC verifying stored bundle root against block header.
- 11 new unit tests in `crates/rpc` covering all witness error paths and success cases.

### OPS-3: Observability

- **Prometheus metrics** (`/metrics`): `rpc_request_duration_seconds` HistogramVec
  with `method` label; `record_rpc_call()` helper for manual instrumentation.
- **`/healthz` + `/readyz`**: Kubernetes-compatible aliases for existing
  `/health` and `/ready` endpoints.
- `docs/observability.md`: full metrics reference, tracing guide (env-var control),
  Grafana starter dashboard JSON, Kubernetes probe config.

### OPS-4: RPC Stability & Docs

- **Unified error code table** (`crates/rpc/src/error.rs`): named constants
  `METHOD_NOT_FOUND (-32601)`, `INVALID_PARAMS (-32602)`, `INTERNAL_ERROR (-32603)`,
  `SERVER_ERROR (-32000)`, `NOT_FOUND (-32001)`, `DEV_MODE_REQUIRED (-32002)`,
  `FEATURE_NOT_ENABLED (-32003)`, `LIMIT_EXCEEDED (-32005)` + convenience constructors.
- All magic `-32xxx` literals across `shell_api.rs`, `eth.rs`, `evm.rs`, `admin.rs`
  migrated to named constructors.
- Semantic fix: `shell_getStorageProfile` "not configured" now returns
  `FEATURE_NOT_ENABLED (-32003)` instead of generic `SERVER_ERROR (-32000)`.
- `shell_setBalance` now returns `DEV_MODE_REQUIRED (-32002)` instead of
  `METHOD_NOT_FOUND (-32601)`.
- `docs/rpc-reference.md`: complete method listing for all namespaces
  (`eth_`, `shell_`, `net_`, `web3_`, `admin_`, `debug_`, `evm_`).

### Tests

- 9 AA batch e2e tests (`tests/e2e/aa_batch_test.rs`): `estimateBatch` validation
  and success path, tx submission → mempool, retrieval after mining, receipt fields,
  `AaBundle` persistence through block storage roundtrip.
- 6 AA sponsored gas e2e tests (`tests/e2e/aa_sponsored_test.rs`): paymaster policy
  default shape, `isSponsored` for unknown/regular/sponsored txs, paymaster survives
  block roundtrip, multiple sponsored txs in one block.
- 3 new `error.rs` unit tests; 4 new metrics/health endpoint tests.


## [0.17.0] — 2026-04-21 — Security & Efficiency Hardening

### Security

- **RPC CORS default**: changed from wildcard `*` to `None` (same-origin only); operators must
  explicitly set `cors_allowed_origins` to enable cross-origin access.
- **RPC gas cap**: `eth_call` / `eth_estimateGas` now capped at 50 M gas (previously unbounded,
  allowing CPU-exhaustion DoS).
- **RPC error leakage**: `internal_err()` now logs details server-side and returns a generic
  `"Internal server error"` to callers; user-facing "not found" and "invalid params" errors
  surface correctly via dedicated `not_found_err()` and `invalid_params_err()` helpers.
- **Keystore file permissions**: node startup rejects keystore files with world- or group-readable
  Unix permissions (`chmod 600` enforced on load, not just on create).
- **Slashing wired**: `PoaEngine::slash_authority()` now mutates `PoaConfig.slashed` and
  `is_authority()` excludes slashed validators; previously slashing was logged but had no effect.
- **BodyResponse unicast**: block-body responses now sent directly to the requesting peer instead
  of broadcasting to all peers (eliminates O(n) amplification).
- **Bounded tx-broadcast channel**: replaced `unbounded_channel` with `channel(4096)` + `try_send`
  backpressure; prevents unbounded memory growth under transaction floods.

### Reliability

- **Archive + pruning conflict**: `--storage-profile archive` combined with `--pruning N` now
  returns an early error instead of silently ignoring archive semantics.
- **Error traits**: `RegistryError` and `WindowError` now implement `std::error::Error`,
  enabling proper trait-object error composition.

### Code Quality

- **Large-file split**: `crates/node/src/node.rs` (4 575 lines) split into 6 focused modules;
  `crates/rpc/src/handler.rs` (4 762 lines) split into 7 focused modules.
- **Production unwraps**: remaining 2 production `unwrap()` calls eliminated.

### CI / Supply Chain

- New `supply-chain` CI job: runs `cargo deny check` (license + advisory + ban policy) and
  `cargo audit` (vulnerability scan) on every push and PR.
- Fixes `BodyRequest` / `BodyResponse` missing match arms in `Libp2pNetwork::broadcast()`
  (compile error when `libp2p` feature is enabled).

### Previous release: [0.16.0]

## [0.16.0] — 2026-04-20 — M14: Storage Profile Node Classification

### Added

- **`--storage-profile <archive|full|light>`** — single flag selects full data-retention policy, replacing
  the confusing `--body-retention` / `--witness-retention` pair as the primary UX.

  | Profile | TX bodies | PQ witnesses | proof_replacement_grace | State roots | ~Daily write |
  |---|---|---|---|---|---|
  | `archive` | forever | forever (never replaced by STARK) | u64::MAX | forever | ~12.8 GB/day |
  | `full` *(default)* | forever | 128 blocks | 0 (replaced immediately) | forever | ~1.5 GB/day |
  | `light` | 4096 blocks (~2.3 h) | 64 blocks | 0 | 4096 blocks | ~1 GB fixed |

- `StorageProfile` enum in `crates/node/src/pruning.rs` with `to_pruning_config()` / `from_pruning_config()`.
- `StorageCapability { profile, oldest_body_block }` P2P message — nodes advertise their data-retention level on
  connect and on startup.
- `BodyRequest { start_number, count }` / `BodyResponse { blocks }` P2P messages for historical body back-fill.
- `PeerCapabilityTracker` (`crates/node/src/historical_sync.rs`) — tracks which peers carry which profiles;
  selects best candidate for back-fill requests.
- `HistoricalBodySync` — on profile upgrade (e.g. `light → full`), automatically back-fills missing block
  bodies from archive/full peers in 128-block batches without interrupting consensus.
- `ChainStore::has_body()` and `ChainStore::put_body_only()` — efficient body presence check and selective
  body restore without overwriting witness bundles.
- `Node::oldest_available_body_block()` — binary-search helper exposed in startup capability broadcast.
- `docker-compose.yml` updated: node1=`archive`, node2/node3=`full`.
- `docs/BLOCK_PRUNING_AND_COMPRESSION.md` — new "Storage Profiles" section with profile comparison table,
  data-volume estimates, auto-sync description, and Docker defaults.

### Changed

- `--body-retention` and `--witness-retention` are now `Option<u64>` overrides; when absent, values come from
  the selected profile. Existing scripts providing these flags continue to work unchanged.
- `proof_replacement_grace` is no longer hardcoded to 100; it is now profile-driven (0 for full/light,
  u64::MAX for archive).
- Node startup banner now shows the active profile name and actual retention values instead of the hardcoded
  `bodies=archive` label.

### Previous release: [0.15.0]

## [0.15.0] — 2026-04-18 — M13: wPoA+STARK Signature Aggregation

### Added

- **STARK sig-aggregation** (`crates/stark-prover`): Winterfell-based STARK circuit that aggregates per-transaction Dilithium3 signatures into a single block-level proof, replacing `1952 B pubkey + 3309 B sig` per tx with one shared proof.
- `PubkeyMode` enum (`Embedded` / `Reference`) — first-tx embeds the full key; subsequent txs reference the registered address.
- `StrippedTransaction`, `TxWitness`, `WitnessBundle` — stripped block bodies store only essential fields; full witness data is pruned on schedule.
- `witness_root` + `sig_aggregate_proof` fields in `BlockHeader`.
- Witness RPC endpoint (`shell_getWitness`), witness store, and consensus validation of witness bundles.
- `ProofBacklog` with high-water-mark, background `ProverService` (never blocks block production), `ProofAmendment` struct with P2P gossip.
- Block state machine: `Sealed → Proven → Stripped`.
- `NetworkType` enum (Dev / Testnet / Mainnet) with per-network STARK parameter defaults.
- CLI flags: `--network <dev|testnet|mainnet>`, `--witness-retention <blocks>`, `--body-retention <blocks>`.
- `NodeRole` enum (`Validator` / `ValidatorProver` / `Prover`) with standalone prover node lifecycle.
- Anti-fraud: equivocation propagation, proof validity challenge, rate limiting, window squatting prevention, prover registry + anti-Sybil, enhanced peer scoring.
- Proof orchestration: `ProofMetadata`, level tracking, L2 recursive verifier AIR scaffold, aggregation scheduler (`J3`).
- Prover health (`ProverHealth`), graceful degradation on prover failure.
- Prometheus metrics: `shell_stark_proofs_total`, `shell_stark_proof_latency_seconds`, `shell_stark_backlog_depth`, `shell_stark_amendments_broadcast_total`.

### Performance

| Batch | STARK proof | Raw Dilithium3 | Compression |
|-------|------------|----------------|-------------|
| 5 txs | 3.7 KB | 25.7 KB | **7.1×** |
| 10 txs | 12.7 KB | 52.7 KB | **~4.0×** |

6-hour soak benchmark: **3.4 M proofs, 0 failures, 157 proofs/sec**.

### Previous release: [0.14.0]



### Added

- **Parallel PQVM executor** (`crates/pqvm`): `ConflictMetric` type with `ReadWrite`, `WriteWrite`, and `Incomplete` variants for tracking inter-transaction state conflicts.
- `plan_with_metrics()`: transaction dependency graph builder that returns a `Vec<ConflictMetric>` alongside the execution plan.
- CLI flag `--parallel-pqvm` (default: **OFF**) to opt-in to the parallel execution path.
- CLI flag `--parallel-pqvm-workers <N>` to control the Rayon worker-pool size (default: number of logical CPUs).
- `config/node.example.toml` updated with a `[parallel_pqvm]` section documenting both flags.
- State validation tests: 11 unit tests in `crates/pqvm`, 3 benchmarks in `crates/bench` (`parallel_pqvm_throughput`, `conflict_detection_overhead`, `sequential_baseline`).

### Changed

- `parallel-pqvm` feature is gated behind the CLI flag and disabled on production nodes until further notice.

### Previous release: [0.13.0]

## [0.13.0] — 2026-04-15 — M10: Mainnet Readiness

### Added

**Batch 1 — Production Security**
- RPC TLS termination via `tokio-rustls` (`--rpc-tls-cert` / `--rpc-tls-key`)
- Server-wide request rate limiting middleware (`--rpc-rate-limit`)
- API key authentication for all methods (`--rpc-api-key`)
- P2P message signature verification for GossipSub block/tx broadcasts

**Batch 2 — Developer Ecosystem**
- `shell-sdk` TypeScript/JavaScript SDK (viem-based): PQ address encode/decode, AA transaction builders, `ShellProvider`, HTTP/WS transports
- `sdk-signer`: `ShellSigner` class, Dilithium3 WASM binding, keystore JSON support
- `ShellERC20` and `ShellERC721` reference contracts with PQ-signature `permit`/`mint`
- `shell-node wallet` CLI commands: `create`, `balance`, `send`, `export`

**Batch 3 — wPoA Consensus**
- Weighted Proof-of-Authority (`WPoaEngine`) with stake-weighted round-robin proposer selection
- `ValidatorSet`: genesis population, weighted proposer, lifecycle state machine (Pending → Active → Exiting → Exited)
- `SlashingEngine`: double-sign detection, offline detection, configurable slash fractions
- Validator lifecycle CLI: `shell-node validator register / status / exit`
- RPC methods: `shell_getValidatorSet`, `shell_getValidatorInfo`

**Batch 4 — Operations & Observability**
- Structured JSON logging with `--log-format json|text` and sensitive-field filtering
- Extended Prometheus metrics: `shell_aa_tx_total`, `shell_key_rotation_total`, `shell_validator_weight`, `shell_consensus_slot_miss`, `shell_pqvm_gas_used_total`, `shell_snapshot_size_bytes`
- Admin RPC namespace (`admin_nodeInfo`, `admin_peers`, `admin_addPeer`, `admin_removePeer`, `admin_datadir`); requires `--admin-api` flag (loopback-only by default)
- Hot backup / restore CLI: `shell-node backup create|restore|schedule`

**Batch 5 — Performance**
- Criterion benchmark suite (`crates/bench/`): `bench_crypto`, `bench_state`, `bench_consensus`
- LRU account cache on `WorldState` (default 64 MiB, `--state-cache-size-mb`): write-through, None-caching, configurable capacity
- Mempool tuning CLI flags: `--mempool-max-size` (default 4096), `--mempool-price-bump` (default 10%)

**Batch 6 — QA & Release**
- `tests/e2e/wpoa_regression.rs`: 14 regression tests covering wPoA, slashing, WorldState LRU cache, mempool priority
- `tests/e2e/throughput_test.rs`: in-process 500 TPS baseline tests
- `fuzz/` directory with three `cargo-fuzz` targets: `fuzz_rlp`, `fuzz_rpc`, `fuzz_p2p_msg`
- `deny.toml` for `cargo deny` security policy (advisory, license, and ban checks)
- `run-load-test.sh`: extended with `TX_COUNT` / `DURATION` env vars for 500 TPS / 1h production soak (`TX_COUNT=1800000 DURATION=3600`)
- `run-security-audit.sh`: M10 checks — admin RPC exposure, slash evidence replay guard, TLS downgrade prevention
- `UPGRADE.md`: migration guide from v0.9 → v0.13.0
- `scripts/release.sh`: automated git tagging and release procedure

### Changed
- Workspace version bumped from `0.6.0` to `0.13.0`
- Dockerfile updated with `--platform` multi-arch comment and `arm64` build note
- `NodeConfig`: added `state_cache_size_mb` (default 64), `mempool_max_size`, `mempool_price_bump` fields

### Fixed
- F-379: `WorldState::snapshot()` LRU capacity rounding drift documented
- F-380: WorldState LRU cache now covered by regression tests
- F-381: `PoaEngine::proposer_for_block` private field — bench uses inline modulo
- F-382: Prometheus cache metrics deferred to M11

### Added
- Native Account Abstraction guide covering `pq1...` addresses, validation layers, custom validator flow, and rollout boundaries

### Changed
- README, quickstart, RPC API, PQ crypto, smart contract, and operator docs aligned to the native AA / `pq1...` address model
- JSON-RPC documentation updated to describe `eth_gasPrice` as a dynamic base-fee value instead of a fixed 1 gwei example

## [0.6.0] — 2026-04-06 — Public Testnet Launch Readiness

### Added
- CORS middleware and configurable API namespace whitelist for RPC server
- Rate limiting on RPC endpoints to prevent abuse
- RLP dual-format transaction encoding for Ethereum tooling compatibility
- Full-featured CLI with TOML config parsing, `tx send/deploy/call`, and account management commands
- Production Docker Compose with multi-node orchestration and monitoring stack
- Prometheus + Grafana example monitoring configurations
- Operator guide, API reference, quickstart guide, and post-quantum crypto documentation
- Comprehensive end-to-end smoke tests, stress tests, and sync tests
- CHANGELOG.md with full milestone history
- README.md with project overview and architecture

### Fixed
- 9 cross-cutting audit findings from M5 consolidated audit (F-301 through F-309)
- RPC audit findings F-310, F-311, F-315 (input validation, error handling)
- Infrastructure and CLI audit findings from B2/B3 review
- Documentation audit findings F-335, F-336, F-337, F-338, F-340

### Changed
- Version bump to 0.6.0 across all workspace crates
- Updated `web3_clientVersion` and `shell_getNodeInfo` version strings

## [0.5.0] — 2026-04-05 — EVM Compatibility & Security Hardening

### Added
- Upgrade from Shanghai to Cancun EVM specification
- EIP-2930 access list support in transactions, PQVM execution, and RPC
- EIP-4844 basic blob transaction type and gas pricing
- `debug_traceTransaction` and trace API for transaction debugging
- Missing standard Ethereum JSON-RPC methods (full eth_* coverage)
- Comprehensive Ethereum tooling compatibility verification tests
- State pruning with configurable retention policy
- Batch parallel signature verification with Rayon
- RLP serialization replacing JSON in chain store for performance
- Comprehensive benchmark suite with Criterion

### Fixed
- Crypto security hardening: 6 audit findings in PQ signature handling
- Consensus security hardening: 7 audit findings in PoA engine
- RPC & filter security hardening: 11 audit findings in JSON-RPC layer
- Storage & CLI security hardening: 8 audit findings
- Network security hardening: 3 audit findings in P2P layer
- Validator set bounds check in `produce_block` (F-202)
- Block import transaction validation and mempool size check (F-181, F-182)
- Access list RLP encoding and size caps (F-171, F-172)
- Unsafe zeroize removed, replaced with `Zeroizing` wrapper (F-150, F-151)

## [0.4.0] — 2026-04-04 — Consensus Finality & Validator Management

### Added
- Finality tracker with epoch-based finalization
- Fork choice rule with longest-chain and finality awareness
- Snapshot manager for fast state sync
- Attestation broadcast over P2P network
- Reorg engine with world state rollback
- Dynamic validator set with world state registry
- `shell_addValidator` / `removeValidator` admin RPCs
- `shell_proposeAddValidator` / `proposeRemoveValidator` governance RPCs
- Governance query RPCs (validatorStatus, governanceInfo, estimateGas)
- ValidatorRegistry native system contract in EVM
- Checkpoint sync (`--checkpoint-url`) in CLI and node
- `eth_subscribe` / `eth_unsubscribe` for newHeads, logs, newPendingTransactions, and syncing
- `eth_newFilter`, `eth_newBlockFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`
- Finality-related RPC support
- 31 comprehensive finality, fork choice, and PoA engine tests
- 18 sync and node integration tests

### Fixed
- Equivocation rejection and world state restore on reorg (F-076, F-083)
- Full transaction support in block responses, sync timeout, unified block tags (F-133, F-134, F-099)
- Filter cap and TTL cleanup scheduling (F-116, F-117)
- Audit findings F-072 through F-075 in RPC layer
- P1 robustness audit findings F-136, F-155, F-157
- P1 audit findings F-078, F-080, F-118, F-119, F-121

## [0.3.0] — 2026-04-03 — Execution Pipeline

### Added
- EIP-1559 dynamic base fee calculation with effective gas pricing
- `eth_gasPrice` RPC and `eth_feeHistory` support
- WebSocket transport alongside HTTP for RPC
- `eth_getLogs` with bloom filter fast-path
- Epoch-based PoA consensus with dynamic validator support
- Receipt retrieval by block number and transaction hash
- Transaction gossip — broadcast transactions to connected peers
- Logs bloom filter computation from receipt logs
- State root tracking with pruning readiness
- Prometheus metrics endpoint
- Kademlia DHT for global peer discovery
- GossipSub peer scoring for block and transaction topics
- Bootstrap node configuration in genesis and CLI
- NAT traversal with relay, DCUtR, and autonat
- TLS configuration support for WSS transport
- `shell_getNodeInfo`, `shell_getNetworkStats`, `shell_getChainStats` dashboard RPCs
- Standard `web3_*`, `net_*`, `eth_*` RPC methods for tooling compatibility
- `--log-format json` for structured logging
- Enhanced `/health` endpoint with detailed node status

### Fixed
- Effective gas price in transaction responses (F-055)
- Log connection errors for NAT traversal debugging (F-054)
- Audit findings F-047 through F-053
- 8 review findings from board #15 (F-039 through F-046)

## [0.2.0] — 2026-04-02 — Storage & Consensus

### Added
- RocksDB storage backend with 4 column families
- Merkle Patricia Trie for state root computation
- WorldState manager for account state
- PoA consensus engine with pluggable trait
- Genesis block initialization from config
- Code storage and PQ public key registry in ChainStore
- PQVM executor with revm integration
- PQ precompiles — disabled `ecrecover`, added Dilithium3 verify
- Transaction validation pipeline with hybrid pubkey registration
- JSON-RPC server with `eth_*` and `shell_*` endpoints
- `eth_call`, `eth_estimateGas`, `eth_getCode`, `eth_getStorageAt`
- `sendRawTransaction` implementation
- Mempool with PQ signature validation and fee-priority ordering
- Replace-by-Fee support in mempool
- P2P network abstraction with channel-based transport
- libp2p networking with GossipSub and mDNS
- Node harness with block production, async event loop, and RPC
- Block seal verification for imported blocks
- Chain sync protocol (BlockRequest / BlockResponse)
- Docker 3-node testnet E2E test harness
- PQ keystore with argon2id + XChaCha20-Poly1305 encryption
- CLI binary with `run`, `init`, `key` subcommands
- `export-state`, `import-state`, `removedb`, `version` CLI subcommands
- RocksDB persistent storage backend with chain resumption

### Fixed
- Deterministic MessageId with BLAKE3, toggleable mDNS (F-031, F-032)
- Cap BlockRequest count to 128 to prevent OOM DoS (F-033)
- Typed GapDetected error prevents sync amplification DoS (F-037)
- Password echo suppression with rpassword (F-030)
- Balance check in mempool (F-020), v/r/s compat fields (F-022)
- Checked arithmetic in gas cost calculation (F-015)
- Configurable RocksDB tuning parameters (F-018)
- DNS transport + mDNS dial + active sync for Docker E2E
- Non-root container user, polling-based sync wait (F-035, F-036)

## [0.1.0] — 2026-04-01 — Foundation

### Added
- `shell-primitives` crate: Keccak-256, BLAKE3, H256, Address, U256, Bytes types
- `shell-crypto` crate: CRYSTALS-Dilithium signing and verification
- SPHINCS+ signer with multi-algorithm verification support
- `shell-core` crate: Block, Transaction (AA-native), Account, Receipt types
- Native account abstraction with pluggable signature schemes
- Post-quantum address derivation (`keccak256(pq_pubkey)[12..]`)
- MIT license and open-source scaffolding
- Workspace structure with modular crate architecture

### Fixed
- 9 immediate review findings (F-002 through F-015)
- M1 review findings for primitives, crypto, and core crates
- 4 review findings (F-005, F-007, F-009, F-010)
- 3 review findings (F-011, F-012, F-013) with F-014 documentation
