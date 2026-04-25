//! M10 In-Process Throughput Test — Sustained 500 TPS baseline
//!
//! Measures transaction submission throughput using the in-memory test harness
//! (no Docker). Validates that the node can accept >= 500 TPS at the RPC layer
//! and that the mempool correctly orders and bounds the result.
//!
//! These tests validate Batch 6.2 (load-test) target for the 500 TPS milestone.
//! They are fast (~100ms) and use no networking — they measure pure in-memory
//! submit latency, providing a lower bound for real-network throughput.

use std::time::Instant;

use shell_primitives::{Address, U256};
use shell_rpc::api::ShellApiServer;

use shell_e2e::{make_funded_account, make_transfer, setup, sign_tx, TEST_CHAIN_ID};

/// Release-build TPS target. Debug builds use a lower threshold automatically.
#[cfg(not(debug_assertions))]
const TARGET_TPS: u64 = 500;
#[cfg(debug_assertions)]
const TARGET_TPS: u64 = 200;

/// Measure raw transaction ingestion rate over `count` transactions from
/// multiple independent funded senders. Each sender submits one transaction
/// to avoid nonce conflicts. Returns (accepted, elapsed_ms).
async fn submit_n_transactions(count: usize) -> (usize, u128) {
    let env = setup();

    // Pre-fund all senders outside the timed region.
    let senders: Vec<_> = (0..count).map(|_| make_funded_account(&env)).collect();
    let recipient = {
        let mut b = [0u8; 20];
        b[19] = 0xfe;
        Address::from(b)
    };

    let start = Instant::now();

    let mut accepted = 0usize;
    for (i, sender) in senders.iter().enumerate() {
        // Use a unique value per sender to avoid tx-hash collisions (the pool
        // deduplicates by tx hash which covers only unsigned fields).
        let tx = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1u64 + i as u64));
        let signed = sign_tx(&sender.signer, sender.address, tx);
        if env.handler.send_transaction(signed).await.is_ok() {
            accepted += 1;
        }
    }

    let elapsed_ms = start.elapsed().as_millis();
    (accepted, elapsed_ms)
}

/// Read the TPS target from the environment.
/// Defaults to `TARGET_TPS` when the variable is absent or unparseable.
/// Set `SHELL_TPS_TARGET=0` to disable the TPS assertion entirely.
fn tps_target() -> u64 {
    std::env::var("SHELL_TPS_TARGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(TARGET_TPS)
}

#[tokio::test]
async fn throughput_500_transactions_baseline() {
    let count = 500usize;
    let (accepted, elapsed_ms) = submit_n_transactions(count).await;

    let acceptance_rate = accepted * 100 / count;
    assert!(
        acceptance_rate >= 95,
        "acceptance rate {acceptance_rate}% below 95% ({accepted}/{count} accepted)"
    );

    let tps = (accepted as u128 * 1000).checked_div(elapsed_ms).unwrap_or(u128::MAX);

    println!("[throughput] {accepted}/{count} tx accepted in {elapsed_ms}ms — {tps} TPS");

    // In-process submit rate must exceed the configured TPS target.
    // Override with SHELL_TPS_TARGET=<n> (set to 0 to disable) for CI
    // environments where wall-clock timing is unreliable.
    let target = tps_target();
    if target > 0 {
        assert!(
            tps >= target as u128,
            "in-process TPS {tps} below target {target} TPS (override with SHELL_TPS_TARGET)"
        );
    }
}

#[tokio::test]
async fn throughput_pool_size_respected_under_load() {
    let env = setup();
    let recipient = {
        let mut b = [0u8; 20];
        b[19] = 0xfd;
        Address::from(b)
    };

    // Submit 200 transactions. Default pool size is 4096, so all should fit.
    let count = 200usize;
    let mut accepted = 0usize;
    for i in 0..count {
        let sender = make_funded_account(&env);
        // Unique value per iteration to avoid tx-hash collisions.
        let tx = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1u64 + i as u64));
        let signed = sign_tx(&sender.signer, sender.address, tx);
        if env.handler.send_transaction(signed).await.is_ok() {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, count,
        "all {count} txs should be accepted under default pool limit"
    );
    assert_eq!(
        env.tx_pool.len(),
        count,
        "pool must contain exactly {count} txs"
    );
}

#[tokio::test]
async fn throughput_mixed_workload_ordering() {
    let env = setup();
    let recipient = {
        let mut b = [0u8; 20];
        b[19] = 0xfc;
        Address::from(b)
    };

    let sender_low = make_funded_account(&env);
    let sender_mid = make_funded_account(&env);
    let sender_high = make_funded_account(&env);

    for (sender, priority_fee) in [
        (&sender_low, 100_000_000u64),
        (&sender_mid, 500_000_000u64),
        (&sender_high, 900_000_000u64),
    ] {
        let mut tx = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1u64));
        tx.max_priority_fee_per_gas = priority_fee;
        tx.max_fee_per_gas = 2_000_000_000;
        let signed = sign_tx(&sender.signer, sender.address, tx);
        env.handler
            .send_transaction(signed)
            .await
            .expect("tx accepted");
    }

    let pending = env.tx_pool.pending(3);
    assert_eq!(pending.len(), 3, "all 3 txs must be in the pool");
    assert_eq!(
        pending[0].from, sender_high.address,
        "highest-fee tx must be first"
    );
    assert_eq!(
        pending[2].from, sender_low.address,
        "lowest-fee tx must be last"
    );
}
