//! M10 Regression Test — wPoA Consensus, LRU State Cache, Mempool Priority
//!
//! Validates the key behaviours introduced in M10 Batches 3-5:
//!   - ValidatorSet: genesis population, weighted proposer, lifecycle
//!   - Slashing: double-sign detection, offline detection
//!   - WorldState LRU cache: write-through correctness, cache-hit after warm
//!   - Mempool: priority-fee ordering, replacement tx with bump enforcement
//!
//! These tests use in-memory components only (no Docker / network).

use std::sync::Arc;

use shell_consensus::{
    detect_double_sign, detect_offline, SlashingConfig, ValidatorSet, ValidatorSetConfig,
};
use shell_core::BlockHeader;
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_storage::{KvStore, MemoryDb, WorldState};

use shell_e2e::{make_funded_account, make_transfer, setup, sign_tx, TEST_CHAIN_ID};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_addr(seed: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = seed;
    Address::from(bytes)
}

fn make_header(number: u64, proposer: Address, extra: &[u8]) -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root: ShellHash::ZERO,
        transactions_root: ShellHash::ZERO,
        receipts_root: ShellHash::ZERO,
        logs_bloom: Bytes::default(),
        number,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1_700_000_000 + number,
        extra_data: Bytes::from(extra.to_vec()),
        proposer,
        sig_aggregate_proof: None,
        base_fee_per_gas: 1_000_000_000,
        withdrawals_root: ShellHash::ZERO,
        parent_beacon_block_root: ShellHash::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
        witness_root: None,
    }
}

#[allow(dead_code)]
fn default_slashing_config() -> SlashingConfig {
    SlashingConfig::default()
}

// ── M10-B3: ValidatorSet regression ──────────────────────────────────────────

#[test]
fn validator_set_genesis_population() {
    let addrs: Vec<(Address, u64)> = (1u8..=5).map(|i| (make_addr(i), i as u64 * 10)).collect();
    let vs = ValidatorSet::from_genesis(addrs.clone(), ValidatorSetConfig::default());

    assert_eq!(vs.active_count(), 5);
    for (addr, weight) in &addrs {
        assert!(vs.is_active(addr));
        assert_eq!(vs.get(addr).unwrap().weight, *weight);
    }
}

#[test]
fn weighted_proposer_deterministic() {
    let addrs: Vec<(Address, u64)> = (1u8..=3).map(|i| (make_addr(i), 10)).collect();
    let vs = ValidatorSet::from_genesis(addrs, ValidatorSetConfig::default());

    // Same block number must always yield the same proposer.
    for block_number in [0u64, 1, 7, 999, 1_000_000] {
        let p1 = vs.weighted_proposer(block_number);
        let p2 = vs.weighted_proposer(block_number);
        assert_eq!(
            p1, p2,
            "proposer must be deterministic for block {block_number}"
        );
        assert!(p1.is_some(), "proposer must be Some for non-empty set");
    }
}

#[test]
fn validator_slash_removes_from_active_set() {
    let addr = make_addr(1);
    let mut vs = ValidatorSet::from_genesis(vec![(addr, 100)], ValidatorSetConfig::default());
    assert!(vs.is_active(&addr));

    vs.slash(&addr, 0).unwrap();
    assert!(!vs.is_active(&addr), "slashed validator must not be active");
}

#[test]
fn validator_enqueue_and_activate() {
    let seed_addr = make_addr(1);
    let mut vs = ValidatorSet::from_genesis(vec![(seed_addr, 10)], ValidatorSetConfig::default());

    let new_addr = make_addr(99);
    vs.enqueue(new_addr).unwrap();
    assert!(
        !vs.is_active(&new_addr),
        "queued validator is not yet active"
    );

    vs.process_activations(1);
    assert!(
        vs.is_active(&new_addr),
        "validator must be active after epoch advance"
    );
}

// ── M10-B3: Slashing regression ──────────────────────────────────────────────

#[test]
fn double_sign_detected_for_same_slot() {
    let proposer = make_addr(1);
    let h1 = make_header(100, proposer, b"branch-a");
    let h2 = make_header(100, proposer, b"branch-b");

    let record = detect_double_sign(&h1, &h2);
    assert!(
        record.is_some(),
        "double-sign must be detected for same block number"
    );
    assert_eq!(record.unwrap().validator, proposer);
}

#[test]
fn no_double_sign_for_different_slots() {
    let proposer = make_addr(1);
    let h1 = make_header(100, proposer, b"branch-a");
    let h2 = make_header(101, proposer, b"branch-b");

    let record = detect_double_sign(&h1, &h2);
    assert!(
        record.is_none(),
        "different block numbers are not a double-sign"
    );
}

#[test]
fn no_double_sign_same_header() {
    let proposer = make_addr(1);
    let h = make_header(100, proposer, b"");
    assert!(
        detect_double_sign(&h, &h).is_none(),
        "identical headers are not a double-sign"
    );
}

#[test]
fn offline_detection_below_threshold() {
    let proposer = make_addr(2);
    let config = SlashingConfig {
        offline_window_blocks: 50,
        ..SlashingConfig::default()
    };
    // 5 blocks gap (100 → 105) — below default window of 50.
    let record = detect_offline(&proposer, 100, 105, &config);
    assert!(
        record.is_none(),
        "5 missed blocks < window 50 should not slash"
    );
}

#[test]
fn offline_detection_above_threshold() {
    let proposer = make_addr(2);
    let config = SlashingConfig {
        offline_window_blocks: 5,
        ..SlashingConfig::default()
    };
    // gap = 110 - 100 = 10 > window 5 → slash
    let record = detect_offline(&proposer, 100, 110, &config);
    assert!(
        record.is_some(),
        "gap > window should trigger offline slash"
    );
}

// ── M10-B5: WorldState LRU cache regression ───────────────────────────────────

#[test]
fn world_state_cache_write_through() {
    let db = Arc::new(MemoryDb::new());
    let mut ws = WorldState::new(db);

    let addr = make_addr(1);
    ws.set_balance(&addr, U256::from(42_000u64)).unwrap();

    let bal1 = ws.get_balance(&addr).unwrap();
    assert_eq!(bal1, U256::from(42_000u64));

    ws.set_balance(&addr, U256::from(99_000u64)).unwrap();
    let bal2 = ws.get_balance(&addr).unwrap();
    assert_eq!(
        bal2,
        U256::from(99_000u64),
        "cache must reflect latest write"
    );
}

#[test]
fn world_state_cache_hit_after_warm() {
    let db = Arc::new(MemoryDb::new());
    let mut ws = WorldState::new(Arc::clone(&db));

    let addr = make_addr(7);
    ws.set_balance(&addr, U256::from(1_000_000u64)).unwrap();
    let root = ws.state_root().unwrap();

    // Re-open with an empty account cache, then populate it from the trie.
    let ws = WorldState::at_root(Arc::clone(&db), &root).unwrap();
    let account = ws.get_account(&addr).unwrap();
    assert_eq!(account.as_ref().unwrap().balance, U256::from(1_000_000u64));

    // Remove the backing trie. A second successful read proves the warmed
    // account was served from the LRU rather than storage.
    for (key, _) in db.scan_all().unwrap() {
        db.delete(&key).unwrap();
    }

    assert_eq!(ws.get_account(&addr).unwrap(), account);
}

#[test]
fn world_state_missing_account_cached_as_none() {
    let db = Arc::new(MemoryDb::new());
    let ws = WorldState::new(db);

    let addr = make_addr(200);
    let result1 = ws.get_account(&addr).unwrap();
    assert!(result1.is_none());

    let result2 = ws.get_account(&addr).unwrap();
    assert!(result2.is_none());
}

// ── M10-B5: Mempool priority regression ───────────────────────────────────────

#[tokio::test]
async fn mempool_higher_priority_fee_ordered_first() {
    use shell_rpc::api::ShellApiServer;

    let env = setup();
    let alice = make_funded_account(&env);
    let bob = make_funded_account(&env);
    let recipient = make_addr(0xfe);

    // alice pays a low priority fee (100_000_000), bob pays a high priority fee (900_000_000).
    let tx_low = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1u64));
    let tx_low_signed = sign_tx(&alice.signer, alice.address, tx_low);

    let tx_high = {
        let mut t = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1u64));
        t.max_priority_fee_per_gas = 900_000_000;
        t.max_fee_per_gas = 2_000_000_000;
        t
    };
    let tx_high_signed = sign_tx(&bob.signer, bob.address, tx_high);

    env.handler
        .send_transaction(tx_low_signed)
        .await
        .expect("low-fee tx accepted");
    env.handler
        .send_transaction(tx_high_signed.clone())
        .await
        .expect("high-fee tx accepted");

    let pending = env.tx_pool.pending(10);
    assert_eq!(pending.len(), 2, "both txs must be in the pool");
    assert_eq!(
        pending[0].from, tx_high_signed.from,
        "higher priority fee tx must be ordered first"
    );
}

#[tokio::test]
async fn mempool_replacement_requires_fee_bump() {
    use shell_rpc::api::ShellApiServer;

    let env = setup();
    let alice = make_funded_account(&env);
    let recipient = make_addr(0xfe);

    // Original tx.
    let tx_orig = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1u64));
    let tx_orig_signed = sign_tx(&alice.signer, alice.address, tx_orig.clone());
    env.handler
        .send_transaction(tx_orig_signed)
        .await
        .expect("original tx accepted");
    assert_eq!(env.tx_pool.len(), 1);

    // Replacement with only +5% bump — must be rejected (config requires +10%).
    let mut tx_insufficient = tx_orig.clone();
    tx_insufficient.max_fee_per_gas = (tx_orig.max_fee_per_gas as f64 * 1.05) as u64;
    tx_insufficient.max_priority_fee_per_gas =
        (tx_orig.max_priority_fee_per_gas as f64 * 1.05) as u64;
    let tx_insuff_signed = sign_tx(&alice.signer, alice.address, tx_insufficient);
    let result = env.handler.send_transaction(tx_insuff_signed).await;
    assert!(
        result.is_err(),
        "replacement with <10% bump must be rejected"
    );

    // Replacement with +10% bump — must succeed (replaces, pool stays at 1).
    let mut tx_sufficient = tx_orig.clone();
    tx_sufficient.max_fee_per_gas = (tx_orig.max_fee_per_gas as f64 * 1.10) as u64 + 1;
    tx_sufficient.max_priority_fee_per_gas =
        (tx_orig.max_priority_fee_per_gas as f64 * 1.10) as u64 + 1;
    let tx_suff_signed = sign_tx(&alice.signer, alice.address, tx_sufficient);
    env.handler
        .send_transaction(tx_suff_signed)
        .await
        .expect("replacement with >=10% bump must be accepted");
    assert_eq!(env.tx_pool.len(), 1, "replacement must not grow the pool");
}
