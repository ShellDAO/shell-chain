//! In-process transaction-load regression tests.
//!
//! These deterministic tests verify admission, ordering, and pool bounds. The
//! production throughput target is exercised by `run-load-test.sh`.

use shell_primitives::{Address, U256};
use shell_rpc::api::ShellApiServer;

use shell_e2e::{make_funded_account, make_transfer, setup, sign_tx, TEST_CHAIN_ID};

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
