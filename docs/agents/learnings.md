# Shell-Chain Learnings (distilled from 297 session checkpoints)

> Each entry: Lesson + Source + Rule. Patterns burned in by real production bugs on
> `shell-testnet-sg3` during the v0.22.x STARK prover hardening campaign (cp 270–296).
> **Read before touching shell-chain prover, storage, or ops code.**

---

## Build & Lint

### L-01: Always run `make ci` locally before pushing

- **Source**: cp 296 — clippy `-D warnings` caught `unnecessary_cast`, `len_zero`,
  `doc_overindented_list_items`, and `dead_code` in the v0.22.2 release PR, blocking CI.
- **Rule**: `make ci` runs in order: `cargo fmt --check` → `cargo clippy --workspace -- -D warnings`
  → `cargo test --workspace`. CI uses the stable toolchain pinned in `rust-toolchain.toml`.
  All three must pass before push.
- **Specific gotchas from cp 296**:
  - `unnecessary_cast`: `gap as u64` where `gap: u64` already (inner value of `Option<u64>`
    from `diagnose_stall()` is already u64).
  - `len_zero`: `backlog.len() == 0` → use `backlog.is_empty()`.
  - `manual_is_multiple_of`: `x % 2 == 0` → `x.is_multiple_of(2)` (stable since Rust 1.87).
  - `doc_overindented_list_items`: `///` list items use 4-space indent; use 2-space.
  - `dead_code`: scaffolded struct fields need `#[allow(dead_code)]` or removal.

---

### L-02: Scaffolded dead-code fields must be annotated before push

- **Source**: cp 296 — `ProverOrchestratorBoundary.l2_job_store` (added for L2 STARK scaffold,
  never read in the current binary) caused CI failure on the release PR.
- **Rule**: Gate scaffold fields behind `#[cfg(feature = "...")]` or annotate with
  `#[allow(dead_code)]` + `// TODO: remove when wired`. Never push a struct field with no
  readers and no annotation — clippy `-D warnings` will block the PR.
- **Common gotcha**: `doc_overindented_list_items` only fires on Rust ≥ 1.87 clippy. A locally
  older toolchain won't warn; the pinned CI toolchain will still catch it.

---

### L-03: `rust-toolchain.toml` is the single toolchain authority — never override ad hoc

- **Source**: cp 259, cp 268 — `rustup override set nightly` during debugging caused `cargo fmt`
  to silently reformat differently from CI pinned stable, producing spurious diffs on push.
- **Rule**: The stable channel in `rust-toolchain.toml` (with `rustfmt` + `clippy` components)
  is immutable without a tracked decision. Never `cargo +nightly` for committed code. Before
  every SG3 remote build, run `rustup show` to confirm the active toolchain version.
- **Common gotcha**: `cargo fmt` on nightly can produce different brace/comma placement in match
  arms. CI `cargo fmt --check` will fail with cryptic diffs that look like whitespace noise.

---

### L-04: Function signature changes cascade — enumerate ALL call sites before committing

- **Source**: cp 289 — adding `stark_frontier: u64` to `prune_before()` caused E0061 at 5
  call sites across 3 crates. One was missed locally and only caught during SG3's 3-minute
  native build, adding 30 minutes of red-build loop.
- **Rule**: Before changing any public function's arity:
  `grep -rn '<fn_name>(' shell-chain/crates shell-chain/tests --include='*.rs'`
  Update every call site in the same commit. Add a `#[deprecated]` shim if backward compat
  is needed. Never commit a signature change without running the grep first.
- **Common gotcha**: `benches/` and `tests/integration/` directories are missed by naive
  crate-local searches. The compiler error on SG3 will surface the missed site — but you've
  already paid 3 minutes of upload + build time.

---

## Cross-Platform

### L-05: Never cross-compile Mac arm64 → SG3 x86_64; build natively on the server

- **Source**: cp 275, cp 291 — a macOS arm64 binary `scp`'d to SG3 produced
  `Exec format error: /usr/local/bin/shell-node` on startup. The old binary had to be restored
  from `.bak` to restore testnet service.
- **Rule**: Correct SG3 deploy workflow: `rsync` source to `/opt/shell-chain-src/worktree`,
  SSH to SG3, then:
  ```
  ~/.cargo/bin/cargo build --release -p shell-cli --features rocksdb,libp2p
  ```
  After build: `file target/release/shell-node` must show `ELF 64-bit LSB executable, x86-64`.
  **Never** `scp` a macOS-compiled binary directly to SG3.
- **Common gotcha**: macOS `file` on a local build shows `Mach-O 64-bit executable arm64`.
  If you see that, stop. Verify with `file /usr/local/bin/shell-node` on SG3 post-deploy.

---

### L-06: Always keep a timestamped `.bak` of the running binary before replacing it

- **Source**: cp 275, cp 283 — broken builds overwrote the running binary with no backup;
  recovery required pulling the tagged release from GitHub, adding ~20 min of downtime.
- **Rule**: Before replacing `/usr/local/bin/shell-node`:
  ```
  cp /usr/local/bin/shell-node "/usr/local/bin/shell-node.$(date +%Y%m%d-%H%M%S).bak"
  ```
  If the new binary fails startup: `cp $(ls -t /usr/local/bin/shell-node.*.bak | head -1) /usr/local/bin/shell-node && systemctl restart shell-node`.
  Clean old `.bak` files after 10 minutes of confirmed stable operation.
- **Common gotcha**: `systemctl is-active shell-node` returns `active` even if the process is
  looping on a panic. Always also check `journalctl -u shell-node -n 20 --no-pager`.

---

## STARK & Prover

### L-07: 0-tx/empty blocks are covered by a contiguous L1 proof range — never proved standalone

- **Source**: cp 269 (design), cp 271, cp 279, cp 280 — the original "force-pop at tail" logic
  sent `prove_sig_batch([])` → `Err("cannot prove empty batch")`, wasting prover cycles.
- **Rule**: `is_stark_compression_source` returns `true` for all canonical blocks including
  0-tx ones (falls back to header lookup). This is intentional — they're seeded for range
  coverage. The `MIN_L1_STARK_TXS = 512` threshold prevents them from being popped standalone.
  Never add a "force pop at tail/gap-boundary" bypass.
- **Corollary**: STARK mint reward counts only non-empty source blocks (`tx_count > 0`). 0-tx
  continuity blocks do not inflate validator reward.
- **Common gotcha**: High `frontier_lag` on a quiet testnet is **correct behavior**, not a
  prover bug. Do not report `frontier_lag > 1000` alone as a stall.

---

### L-08: `MIN_L1_STARK_TXS = 512` is a hard floor with no bypass conditions

- **Source**: cp 275, cp 280 — every attempt to lower or bypass this constant caused worse
  bugs: empty batch errors, or prover deadlocks on all-empty historical blocks.
- **Rule**: `pop_contiguous_with_min_entries(max_sources=1024, min_entries=512)` returns `None`
  unconditionally when `entries < 512` regardless of tail position, gap presence, or elapsed
  time. Do not lower this constant; the STARK circuit requires a minimum input size. Use
  `shell-stress.service` (64 workers, 25–31 TPS) to maintain load above the threshold.
- **Common gotcha**: The extension scan cap is `DEFAULT_MAX_L1_RANGE_SOURCES × 4 = 4096` blocks,
  not 1024. The 4× overrun prevents deadlock when a long 0-tx prefix precedes the first tx block.
  Do not reduce the overrun cap.

---

### L-09: The drain-reseed infinite loop — root cause and `stark_drain_frontier` fix

- **Source**: cp 292–296 (the final blocking bug before v0.22.2; verified fix: `frontier_lag`
  4807 → 1 within 5 minutes on SG3)
- **Root cause**: A sparse block range (< 512 entries) before a gap in `settled_stark_sources`
  causes an eternal cycle: 60s drain → `needs_reseed` → seeder recomputes `scan_start` from
  `settled_l1_count` (never advances past the gap because proofs never settle for sub-512
  ranges) → same blocks re-inserted → drain → repeat.
- **Fix**: `Arc<AtomicU64> stark_drain_frontier` shared between `Node<S>` and `ProverService`.
  After `drain_front(take)`: `fetch_max(gap_at_block, Ordering::Release)`.
  In seeder: `scan_start = max(contiguous_pending_end − 16, drain_frontier.load(Acquire))`.
- **Properties**: Lock-free, zero overhead on the seeding hot path. Resets to 0 on restart
  (safe: one extra drain fires, then the fix re-applies). Must be wired through
  `ProverServiceConfig::with_drain_frontier()` — any future refactor must preserve this wire.

---

### L-10: Two-tick gap confirmation before draining — prevent premature drain on catch-up

- **Source**: cp 297 — Copilot review comment on PR #43 identified that a single-check drain
  could prematurely empty a backlog mid-burst catch-up where entries transiently dip below 512.
- **Rule**: `ProverService` tracks `consecutive_gap: (u64, u32)` (gap block, consecutive-count).
  Only call `backlog.drain_front()` after ≥ 2 consecutive 60s observations of the same gap
  block. Reset the counter whenever the gap block changes or disappears.
- **Common gotcha**: `diagnose_stall()` returns `Option<u64>`; inner value is already `u64`.
  Do not cast it: `gap_block as u64` triggers `unnecessary_cast` (see L-01).

---

### L-11: Old amendment end-blocks create backlog gaps — fix with `tasks.retain()`

- **Source**: cp 287, cp 288 — root cause of "0 proofs generated" after the first successful
  proof: old `ProofAmendment` end-block N was pushed to `pending_stark_settlements` and skipped,
  but blocks 0..N-1 (the amendment's source blocks, already in `tasks`) remained in the backlog,
  creating a gap at N that made `pop_contiguous_with_min_entries` return `None` forever.
- **Rule**: After identifying an old valid amendment in `enqueue_stark_frontier_backlog`,
  before the `continue`: call `tasks.retain(|t| !amendment.source_hashes.contains(&t.block_hash))`
  and recompute `seeded_entries` and `queued` accordingly.
- **Common gotcha**: The `retain` must run **before** the `continue`. If it runs after, the
  covered blocks remain in `tasks` for this iteration and get inserted on the next seeding call.

---

### L-12: `scan_start` must use `contiguous_pending_end`, not raw `pending_max_block`

- **Source**: cp 291, cp 292 (Fix B) — raw `pending_max_block` jumped `scan_start` to the chain
  tip, seeding brand-new tip blocks instead of continuing the historical sequence, producing
  tip proofs that always failed ordering validation.
- **Rule**: Compute `contiguous_pending_end` by walking sorted pending amendment block numbers
  from `settled_l1_count` upward, stopping at the first gap. Then:
  `scan_start = max(settled_l1_count, contiguous_pending_end).saturating_sub(16)`.
  The 16-block lookback ensures the seeder never misses the last settled boundary.
- **Common gotcha**: `pending_amendments.keys().max()` is WRONG — it returns the highest pending
  block (possibly tip), not the end of the contiguous settled+pending run.

---

### L-13: Ordering validation must overlay pending settlements, not just settled sources

- **Source**: cp 285 — consecutive proofs 2..N all failed ordering ("must start at frontier #X")
  because `settled_stark_sources` did not yet contain proof 1 (pending, not yet mined). Only
  the first proof ever succeeded.
- **Rule**: In `validate_stark_amendment_ordering`, build the overlay from BOTH
  `settled_stark_sources` (canonical) AND `pending_stark_settlements` (queued-not-yet-mined)
  before calling `validate_stark_amendment_ordering_with_overlay`. Proofs arrive faster than
  blocks; the overlay must reflect the full in-flight frontier.
- **Common gotcha**: `first_canonical_block_below_layer` defaults to an O(n) scan from block 0.
  On a 120k-block chain this blocks for minutes. Optimize:
  `scan_start = (settled_count + overlay_count).saturating_sub(16)`.

---

### L-14: Tip-loop rejection — delete all amendment artifacts on ordering failure

- **Source**: cp 291 — 400+ rejection counter spinning: stale `ProofAmendment` artifacts in
  `amendment_store` reloaded on every restart, re-queued as proof tasks, generated out-of-order
  tip proofs, failed ordering, incremented counter, repeat.
- **Rule**: In the `prover_amendment_rx` handler (event_loop.rs ~line 307), when a locally-
  generated proof fails ordering: delete ALL artifacts for that block from `amendment_store`
  and log at `WARN`. Without the delete, the artifact persists through restarts.
- **Diagnosing rejection spikes**: rejections increment at `DEBUG` level — invisible at
  `RUST_LOG=info`. To diagnose, temporarily add to the service env:
  `RUST_LOG=info,shell_node::node::event_loop=debug,shell_node::node::system_rewards=debug`.
  Revert after collection (see L-19). Up to ~20 rejections during initial catch-up is normal.

---

## Storage

### L-15: Witness pruner STARK guard — never prune witnesses for unproved blocks

- **Source**: cp 288, cp 289 — `DEFAULT_WITNESS_RETENTION = 128` pruned witnesses for
  blocks 62001–111372 (49k+ blocks) before the prover reached them on SG3. Those became
  permanent backlog gaps: `has_bundle()` returns false but `is_stark_compression_source`
  still returns true → seeded, never provable.
- **Rule**: `WitnessPruner::prune_before(cutoff: u64, stark_frontier: u64)` sets effective
  cutoff = `min(cutoff, stark_frontier)` when `stark_frontier > 0`. Pass
  `stark_frontier = settled_stark_sources.count()` from the D1 block handler.
  Pass `stark_frontier = 0` for non-prover nodes and all existing tests.
- **Data loss note**: Witnesses for SG3 blocks 64038–117185 were permanently lost before this
  fix. The `drain_frontier` mechanism (L-09) prevents them from causing an infinite loop, but
  the data is gone — those blocks are unprovable.
- **Common gotcha**: Adding this parameter causes E0061 at all call sites (see L-04).
  Every test must be updated to pass `0` explicitly or it won't compile.

---

### L-16: `settled_stark_sources` is live — updated by BOTH block_producer AND block_importer

- **Source**: cp 285 — early assumption that `settled_stark_sources` was rebuilt only at startup
  was wrong. `record_settled_sources` is called on every canonical block (both self-produced
  and imported), keeping the set live.
- **Rule**: `settled_stark_sources: Arc<Mutex<HashSet<(u8, ShellHash)>>>` is updated at startup
  by `rebuild_settled_stark_sources_from_chain` AND at runtime by `record_settled_sources` on
  every canonical block. Never guard `record_settled_sources` behind `is_block_producer` —
  validator nodes receiving proofs via gossip also need the set updated on block import.
- **Common gotcha**: Never call `rebuild_settled_stark_sources_from_chain` from a hot path —
  it scans the full chain (O(chain_len)) and will block for minutes on a 120k-block testnet.

---

## Ops

### L-17: Use systemd topology — the Docker compose files are reference-only

- **Source**: cp 268, cp 283 — running `docker compose up` on SG3 conflicted with the live
  systemd service and corrupted the data directory lock.
- **Rule**: SG3 service lifecycle is `systemctl {start,stop,restart,status} shell-node` only.
  Key paths: binary `/usr/local/bin/shell-node`, data `/mnt/shell-data/data/node2`,
  service file `/etc/systemd/system/shell-node.service`, SSH key
  `workspace/ops/shell-chain-testnet/shell-testnet-key.pem`, host `root@47.237.195.95`.
  `workspace/ops/docker/` compose files are archived reference; never `docker compose up` on SG3.
- **Common gotcha**: `systemctl is-active shell-node` returns `active` even when the process is
  looping on a startup panic. Always check `journalctl -u shell-node -n 30 --no-pager`.

---

### L-18: Three-RPC fanout on ports 8545/8547/8549 — check health before blaming the prover

- **Source**: cp 267, cp 268 — when one RPC port went silent, `shell-stress` TPS dropped to
  ~10, `MIN_L1_STARK_TXS = 512` was never met, and the prover silently idled. The operator
  incorrectly attributed this to a prover bug.
- **Rule**: Before investigating any STARK stall, first verify all three RPC ports from SG3:
  `curl -s http://127.0.0.1:8545/ && curl -s http://127.0.0.1:8547/ && curl -s http://127.0.0.1:8549/`
  If any returns connection refused, restart that RPC listener and verify TPS recovery before
  touching the prover. `shell-stress` config: 64 workers, 25–31 TPS, 20s epochs, ~75% CPU target.
- **Common gotcha**: `shell-stress` silently falls back when a port is unresponsive — TPS drops
  but the service logs no error. Check TPS: `curl -s http://127.0.0.1:9090/metrics | grep tx_per_second`.

---

### L-19: Revert debug logging immediately after diagnosis — journald fills within hours

- **Source**: cp 297 — SG3 disk hit 71% used after a multi-day STARK debug session with
  targeted debug logging. `journalctl --vacuum-size=500M` reclaimed ~4 GB (54%).
- **Rule**: Debug-logging lifecycle: (1) enable minimal scope in service env, (2) collect
  ≤ 30 min of logs, (3) revert `RUST_LOG=info` in the service file,
  (4) `systemctl daemon-reload && systemctl restart shell-node`, (5) `journalctl --vacuum-size=500M`.
  At 30 TPS, STARK debug logs emit ~50 MB/min. The SG3 root partition is ~40 GB.
- **Common gotcha**: Forgetting `systemctl daemon-reload` after editing the service file means
  the old environment variables stay active — logging appears reverted but isn't.

---

### L-20: Metrics endpoint is the primary STARK health signal — know the key counters

- **Source**: cp 278, cp 284, cp 290 — `http://127.0.0.1:9090/metrics` is the fastest
  triage point for any STARK liveness issue.
- **Rule**: Quick diagnostic:
  `curl -s http://127.0.0.1:9090/metrics | grep -E 'stark_|frontier_|backlog_'`
  Key signals: `stark_proofs_settled` incrementing = healthy. `frontier_lag` decreasing over
  time with active load = healthy. `stark_rejection_counter` > 50 sustained = investigate L-14.
  `backlog_depth` stuck at max with zero `proofs_generated` = investigate L-09.
- **Common gotcha**: `stark_rejection_counter` increments at `DEBUG` level only. The Prometheus
  value is accurate but the log line is invisible at `RUST_LOG=info`. Use `stark_proofs_settled`
  as the primary liveness signal, not the rejection counter.

---

## Git & Release

### L-21: Squash-merge release branches require `git branch -D` (force-delete) after merge

- **Source**: cp 296, cp 297 — `git branch -d release/v0.22.2` failed with "branch is not
  fully merged" after `ShellDAO/shell-chain` squash-merged PR #43. The squash creates a new
  SHA not reachable from the local branch tip.
- **Rule**: Post-merge cleanup:
  ```
  git fetch upstream && git checkout main && git reset --hard upstream/main
  git push origin main --force-with-lease
  git branch -D release/v0.22.2
  git push origin --delete release/v0.22.2
  ```
  Never `git merge upstream/main` back into a release branch — creates divergent history.
- **Common gotcha**: `git branch -d` succeeds silently on fast-forward merges but fails on
  squash-merges. "Not fully merged" error = squash happened; always use `-D`.

---

### L-22: After upstream squash-merge, sync your fork with `--force-with-lease`

- **Source**: cp 296 — fork's `main` diverged after squash; plain `git push origin main`
  was rejected (non-fast-forward). `--force` without `--lease` is unsafe.
- **Rule**: Safe fork-sync: `git fetch upstream`, `git reset --hard upstream/main`,
  `git push origin main --force-with-lease`. `--force-with-lease` refuses if someone else
  pushed to your fork since your last fetch, protecting against overwriting collaborator commits.
- **Common gotcha**: `--force` (without `--lease`) silently overwrites any commits pushed to
  your fork since last fetch. Always use `--force-with-lease` for fork sync after squash-merge.

---

### L-23: Agent-authored commits require the `🤖` declaration and `Co-authored-by` trailer

- **Source**: cp 268, cp 296, `workspace/github/agent-playbook.md §2`
- **Rule**: Every AI-authored PR/Issue body must begin with `'🤖 本 [Issue/PR] 由 AI Agent 创建'` (Chinese: "This Issue/PR was created by an AI Agent").
  Every commit must end with:
  ```
  Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
  ```
  Language convention: PR/Issue descriptions and review comments → Chinese.
  Commit messages and code comments → English.
- **Common gotcha**: For squash-merges, GitHub uses the PR title as the commit message and the
  PR body as the extended description. Put the `Co-authored-by` trailer in the PR body so
  GitHub's squash UI pre-fills it — individual commit trailers may not survive squash.

---

## Review Process

### L-24: `CONSTITUTION.md` takes precedence — flag drift, never silently reconcile

- **Source**: cp 297, `docs/agents/CONSTITUTION.md`
- **Rule**: Precedence order: Constitution > approved ADRs > spec > code > CHANGELOG/README.
  When any lower-level artifact contradicts the Constitution, do NOT silently update the
  Constitution to match the code. Add `⚠️ CONSTITUTION DRIFT:` in the PR description and
  tag a human maintainer for explicit acknowledgment before merging.
- **Common gotcha**: CHANGELOG entries often describe emergent behavior without cross-checking
  the Constitution. Run a Constitution diff before every release PR (not just breaking changes):
  `grep -n "STARK\|consensus\|reward" docs/agents/CONSTITUTION.md`.

---

### L-25: Multi-role Review Board before merging any STARK or consensus change

- **Source**: cp 270, cp 276, cp 296, `workspace/agents/shared/review/protocol.md` —
  both the drain-reseed loop (L-09) and the witness pruner data-loss bug (L-15) passed
  single-reviewer review, yet both required cross-component reasoning across `ProverService`,
  `WitnessPruner`, and `enqueue_stark_frontier_backlog` simultaneously.
- **Rule**: PRs touching `event_loop.rs`, `system_rewards.rs`, `backlog.rs`,
  `prover_service.rs`, `chain_store.rs`, or `witness_pruner.rs` require all of:
  - `@Architecture` — state machine invariants, design correctness
  - `@Quality` — test coverage, edge cases (empty chain, tip, restart recovery)
  - `@Security` — DoS surface, unbounded accumulation, economic attack vectors
  - `@Harness` — testnet reproducibility on SG3
  - `@PQCrypto` — add for any Dilithium3/SPHINCS+ changes
- **Common gotcha**: "One senior reviewer approved" does NOT satisfy this. The multi-role check
  exists specifically to surface cross-component interactions that a single reviewer will miss.

---

*Last updated: distilled from cp 270–297 (v0.22.x STARK prover hardening campaign).*
*Next review: after v0.23 STARK final-settlement (Option B, async inclusion-block) is deployed.*
